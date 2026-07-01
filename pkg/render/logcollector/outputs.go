// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logcollector

import (
	"fmt"

	"sigs.k8s.io/yaml"

	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/url"
)

// parseUserFilter parses a user-provided filter snippet (the content of a
// fluent-bit-filters ConfigMap key) as a YAML list of fluent-bit filter maps.
func parseUserFilter(content string) ([]map[string]interface{}, error) {
	var filters []map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &filters); err != nil {
		return nil, err
	}
	return filters, nil
}

// InvalidKeys returns the names of the fluent-bit-filters ConfigMap keys whose
// content is non-empty but does not parse as a fluent-bit YAML filter list — for
// example a leftover fluentd <filter> block after an upgrade. addUserFilters skips
// these during render so the pipeline still starts; callers use this to surface the
// misconfiguration to the user without failing the whole LogCollector.
func (f *FluentBitFilters) InvalidKeys() []string {
	if f == nil {
		return nil
	}
	var bad []string
	for _, uf := range []struct{ name, content string }{
		{FluentBitFilterFlowName, f.Flow},
		{FluentBitFilterDNSName, f.DNS},
	} {
		if uf.content == "" {
			continue
		}
		if _, err := parseUserFilter(uf.content); err != nil {
			bad = append(bad, uf.name)
		}
	}
	return bad
}

// addUserFilters inlines the user-provided filter snippets into the pipeline.
// The fluent-bit-filters ConfigMap keys (flow, dns) each hold a YAML list of
// fluent-bit filter maps; entries without an explicit match are scoped to the
// key's log tag. Invalid YAML is skipped (and logged) rather than breaking the
// whole pipeline; the controller surfaces it as a TigeraStatus warning (see
// InvalidKeys).
func (c *fluentBitComponent) addUserFilters(cfg *fluentBitConfig) {
	if c.cfg.Filters == nil || c.cfg.OSType != rmeta.OSTypeLinux {
		return
	}
	for _, uf := range []struct{ content, tag string }{
		{c.cfg.Filters.Flow, "flows"},
		{c.cfg.Filters.DNS, "dns"},
	} {
		if uf.content == "" {
			continue
		}
		filters, err := parseUserFilter(uf.content)
		if err != nil {
			log.Error(err, "skipping invalid user filter content", "tag", uf.tag)
			continue
		}
		for _, f := range filters {
			if _, ok := f["match"]; !ok {
				if _, ok := f["match_regex"]; !ok {
					f["match"] = uf.tag
				}
			}
			cfg.Pipeline.Filters = append(cfg.Pipeline.Filters, f)
		}
	}
}

// hostScopeIncludesCluster reports whether a store's hostScope includes
// cluster logs. Fluentd's envVarsForHostScope semantics: cluster *flow* logs
// are the only cluster type the scope gates (FORWARD_CLUSTER_LOGS_TO_<STORE>),
// and non-cluster flows always ship when the store is enabled
// (FORWARD_NON_CLUSTER_LOGS_TO_<STORE> was true for both All and
// NonClusterOnly).
func hostScopeIncludesCluster(hostScope *operatorv1.HostScope) bool {
	return hostScope == nil || *hostScope != operatorv1.HostScopeNonClusterOnly
}

func (c *fluentBitComponent) addS3Outputs(cfg *fluentBitConfig) {
	s3 := c.cfg.LogCollector.Spec.AdditionalStores.S3
	if s3 == nil {
		return
	}
	// tag → S3 path segment. The segments preserve fluentd's archive layout
	// (the `path` directives in fluentd/outputs/out-s3-*.conf) so existing
	// downstream consumers keep reading the same prefixes. The cluster types
	// below always shipped when S3 was enabled — ee_entrypoint.sh copied their
	// output confs unconditionally under S3_STORAGE=true; only cluster *flows*
	// honored the hostScope gate. WAF, BGP, IDS events and policy activity were
	// never S3-archived (out-s3-waf.conf existed but was never copied).
	type s3Output struct{ tag, path string }
	outputs := []s3Output{
		{"dns", "dns"},
		{"l7", "l7"},
		{"runtime", "runtime"},
		{"audit.tsee", "audit_tsee"},
		{"audit.kube", "audit_kube"},
		{"compliance.reports", "compliance_reports"},
		// Non-cluster flows ship whatever the hostScope. Deliberate delta from
		// fluentd: they land under their own non_cluster_flows/ prefix instead
		// of sharing flows/ — fluent-bit's $INDEX is tracked per output, so two
		// outputs writing one prefix would overwrite each other's objects
		// (fluent-plugin-s3 checked object existence before upload; out_s3
		// does not).
		{"non_cluster_flows", "non_cluster_flows"},
	}
	if hostScopeIncludesCluster(s3.HostScope) {
		outputs = append([]s3Output{{"flows", "flows"}}, outputs...)
	}
	for _, o := range outputs {
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, map[string]interface{}{
			"name":          "s3",
			"match":         o.tag,
			"bucket":        s3.BucketName,
			"region":        s3.Region,
			"s3_key_format": fmt.Sprintf("%s/%s/%%Y%%m%%d_$INDEX.gz", s3.BucketPath, o.path),
			// fluent-plugin-s3's default store_as was gzip, so the legacy
			// archives were gzipped; keep the objects compressed to match
			// their .gz suffix.
			"compression":              "gzip",
			"total_file_size":          "10M",
			"upload_timeout":           fluentBitDefaultFlush,
			"retry_limit":              "no_limits",
			"storage.total_limit_size": "500M",
		})
	}
}

func (c *fluentBitComponent) addSyslogOutputs(cfg *fluentBitConfig) {
	syslog := c.cfg.LogCollector.Spec.AdditionalStores.Syslog
	if syslog == nil {
		return
	}
	proto, host, port, _ := url.ParseEndpoint(syslog.Endpoint)
	mode := proto
	var syslogTags []string
	for _, t := range syslog.LogTypes {
		switch t {
		case operatorv1.SyslogLogAudit:
			syslogTags = append(syslogTags, "audit.tsee", "audit.kube")
		case operatorv1.SyslogLogDNS:
			syslogTags = append(syslogTags, "dns")
		case operatorv1.SyslogLogFlows:
			// Cluster flows are the only type the hostScope gates
			// (FORWARD_CLUSTER_LOGS_TO_SYSLOG); non-cluster flows always ship
			// when the Flows type is enabled — fluentd copied the NCH syslog
			// output (out-syslog-nch.conf) for both All and NonClusterOnly.
			if hostScopeIncludesCluster(syslog.HostScope) {
				syslogTags = append(syslogTags, "flows")
			}
			syslogTags = append(syslogTags, "non_cluster_flows")
		case operatorv1.SyslogLogIDSEvents:
			syslogTags = append(syslogTags, "ids.events")
		}
	}
	for _, tag := range syslogTags {
		out := map[string]interface{}{
			"name":                  "syslog",
			"match":                 tag,
			"host":                  host,
			"port":                  port,
			"mode":                  mode,
			"syslog_format":         "rfc5424",
			"syslog_hostname_key":   "host",
			"syslog_appname_preset": "tigera_secure",
			// The record's host key wins when present (flows/dns/l7/runtime/waf,
			// stamped by record_transformer.lua, and non-cluster flows, stamped
			// by the sending host); the preset is the fallback for tags without
			// it (audit.*, ids.events), matching fluentd's static
			// `hostname SYSLOG_HOSTNAME` (the node name, injected here through
			// fluent-bit's env-var substitution of the NODENAME pod env var).
			"syslog_hostname_preset": "${NODENAME}",
			// No syslog_severity_preset: it is an integer property (a string
			// like "info" would atoi() to 0 = Emergency); the default, 6, is
			// already info — what fluentd's `severity info` sent.
			//
			// The whole record is shipped as one JSON MSG, preserving fluentd
			// remote_syslog's `<format> @type json` wire format: the per-output
			// lua processor below packs the record into the `log` key, so other
			// outputs still see the unpacked record.
			"syslog_message_key": "log",
			"processors": map[string]interface{}{
				"logs": []map[string]interface{}{{
					"name":   "lua",
					"script": c.luaScriptPath(),
					"call":   "syslog_pack",
				}},
			},
			"retry_limit":              "no_limits",
			"storage.total_limit_size": "500M",
		}
		if syslog.Encryption == operatorv1.EncryptionTLS {
			out["mode"] = "tls"
			// `mode tls` only selects the framing; the tls property is what
			// actually enables TLS on the upstream connection.
			out["tls"] = "on"
			out["tls.verify"] = "on"
			if c.cfg.UseSyslogCertificate {
				// The user-provided syslog CA is part of the trusted bundle
				// (fluentd pointed SYSLOG_CA_FILE at the same bundle).
				out["tls.ca_file"] = c.trustedBundlePath()
			}
		}
		if syslog.PacketSize != nil {
			out["syslog_maxsize"] = *syslog.PacketSize
		}
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, out)
	}
}

func (c *fluentBitComponent) addSplunkOutputs(cfg *fluentBitConfig) {
	splunk := c.cfg.LogCollector.Spec.AdditionalStores.Splunk
	if splunk == nil {
		return
	}
	proto, host, port, _ := url.ParseEndpoint(splunk.Endpoint)
	// The log types forwarded to Splunk HEC per the design's mapping table:
	// flows, dns, l7, audit.tsee, audit.kube. As with the other stores,
	// cluster flows are the only type the hostScope gates
	// (FORWARD_CLUSTER_LOGS_TO_SPLUNK), and non-cluster flows always ship.
	tags := []string{"dns", "l7", "audit.tsee", "audit.kube", "non_cluster_flows"}
	if hostScopeIncludesCluster(splunk.HostScope) {
		tags = append([]string{"flows"}, tags...)
	}
	for _, tag := range tags {
		out := map[string]interface{}{
			"name":                     "splunk",
			"match":                    tag,
			"host":                     host,
			"port":                     port,
			"splunk_token":             "${SPLUNK_HEC_TOKEN}",
			"retry_limit":              "no_limits",
			"storage.total_limit_size": "500M",
		}
		// Honor the endpoint scheme like fluentd's SPLUNK_PROTOCOL did: an
		// http:// HEC endpoint stays plaintext, https:// gets verified TLS
		// against the trusted bundle (which carries any private CA).
		if proto != "http" {
			out["tls"] = "on"
			out["tls.verify"] = "on"
			out["tls.ca_file"] = c.trustedBundlePath()
		}
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, out)
	}
}
