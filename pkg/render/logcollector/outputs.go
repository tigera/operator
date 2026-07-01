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

func (c *fluentBitComponent) addS3Outputs(cfg *fluentBitConfig) {
	s3 := c.cfg.LogCollector.Spec.AdditionalStores.S3
	if s3 == nil {
		return
	}
	// The log types fluentd archived to S3 (fluentd/outputs/out-s3-*.conf):
	// BGP, IDS events and policy activity were never S3-archived.
	tags := []string{"flows", "dns", "l7", "waf", "runtime", "audit.tsee", "audit.kube", "compliance.reports"}
	if s3.HostScope != nil && *s3.HostScope == operatorv1.HostScopeNonClusterOnly {
		// Matches fluentd's behavior: FORWARD_NON_CLUSTER_LOGS_TO_S3 only wired
		// S3 into the non-cluster flows path (ee_entrypoint.sh), not DNS or
		// policy activity. The tag is the one the http input derives from
		// voltron's /non-cluster-flows route.
		tags = []string{"non_cluster_flows"}
	}
	for _, tag := range tags {
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs, map[string]interface{}{
			"name":                     "s3",
			"match":                    tag,
			"bucket":                   s3.BucketName,
			"region":                   s3.Region,
			"s3_key_format":            fmt.Sprintf("%s/%s/%%Y%%m%%d_$INDEX.gz", s3.BucketPath, tag),
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
			syslogTags = append(syslogTags, "flows")
		case operatorv1.SyslogLogIDSEvents:
			syslogTags = append(syslogTags, "ids.events")
		}
	}
	for _, tag := range syslogTags {
		out := map[string]interface{}{
			"name":                   "syslog",
			"match":                  tag,
			"host":                   host,
			"port":                   port,
			"mode":                   mode,
			"syslog_format":          "rfc5424",
			"syslog_hostname_key":    "host",
			"syslog_appname_preset":  "tigera_secure",
			"syslog_severity_preset": "info",
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
	// The log types fluentd forwarded to Splunk HEC
	// (fluentd/outputs/out-splunk-{flow,dns,l7,audit}.conf).
	for _, tag := range []string{"flows", "dns", "l7", "audit.tsee", "audit.kube"} {
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
