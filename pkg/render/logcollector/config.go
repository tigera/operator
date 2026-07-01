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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

func (c *fluentBitComponent) fluentBitConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: c.fluentBitConfConfigMapName(), Namespace: LogCollectorNamespace},
		Data:       map[string]string{"fluent-bit.yaml": c.renderFluentBitConf()},
	}
}

func (c *fluentBitComponent) logInputs() []logInput {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return windowsLogInputs
	}
	return linuxLogInputs
}

// logDirsCSV lists the tailed log directories (comma-separated) for the
// pos-migrator init container to pre-create: glob tail inputs (compliance) log
// a scan error on every refresh while their parent directory is missing, e.g.
// on clusters where the producing feature isn't enabled yet. Deriving the list
// from logInputs keeps a single source of truth for the tailed paths.
func (c *fluentBitComponent) logDirsCSV() string {
	var dirs []string
	seen := map[string]bool{}
	for _, in := range c.logInputs() {
		dir := c.path(in.path[:strings.LastIndex(in.path, "/")])
		if !seen[dir] {
			seen[dir] = true
			dirs = append(dirs, dir)
		}
	}
	return strings.Join(dirs, ",")
}

// linseedTags lists the tags shipped to Linseed: every tailed tag except
// ids.events and compliance.reports — those are deliberately not
// Linseed-bound (IDS events use a different ingestion path; compliance
// reports are S3-only). The non_cluster_* tags are produced by the
// voltron-facing http input relaying non-cluster host posts; hosts ship
// flow, DNS and policy activity logs.
func (c *fluentBitComponent) linseedTags() []string {
	var tags []string
	for _, in := range c.logInputs() {
		if in.tag == "ids.events" || in.tag == "compliance.reports" {
			continue
		}
		tags = append(tags, in.tag)
	}
	if c.cfg.NonClusterHost != nil && c.cfg.OSType == rmeta.OSTypeLinux {
		tags = append(tags, "non_cluster_flows", "non_cluster_dns", "non_cluster_policy_activity")
	}
	return tags
}

// linseedBulkURI maps a tag to its Linseed bulk-ingestion URI. Voltron-relayed
// non_cluster_* tags post to the same path as their base tag.
func linseedBulkURI(tag string) string {
	tag = strings.TrimPrefix(tag, "non_cluster_")
	switch tag {
	case "runtime":
		return "/api/v1/runtime/reports/bulk"
	case "audit.tsee":
		return "/api/v1/audit/logs/ee/bulk"
	case "audit.kube":
		return "/api/v1/audit/logs/kube/bulk"
	case "bird", "bird6":
		return "/api/v1/bgp/logs/bulk"
	default:
		// flows, dns, l7, waf, policy_activity
		return fmt.Sprintf("/api/v1/%s/logs/bulk", tag)
	}
}

// splitEndpoint splits an https:// endpoint into the host and port fields
// fluent-bit's native net layer expects (the port defaults to 443). Plain
// string handling: pkg/url's ParseEndpoint rejects endpoints without an
// explicit port, and Linseed endpoints usually carry none.
func splitEndpoint(endpoint string) (string, int) {
	host := strings.TrimPrefix(endpoint, "https://")
	host = strings.TrimSuffix(host, "/")
	port := 443
	if i := strings.LastIndex(host, ":"); i >= 0 {
		if n, err := strconv.Atoi(host[i+1:]); err == nil {
			host, port = host[:i], n
		}
	}
	return host, port
}

// linseedHTTPOutput renders one built-in http output block shipping a tag's
// chunks to its Linseed bulk endpoint. The http output is plain C compiled
// into fluent-bit — no Go proxy plugin is involved — and `format json_lines`
// with the date key disabled produces exactly the NDJSON body Linseed's bulk
// APIs expect. The bearer token file is re-read on every request (a Tigera
// patch carried by the fluent-bit base build), so kubelet-rotated
// ServiceAccount tokens and operator-refreshed managed-cluster tokens are
// picked up without a restart. certPath/keyPath are the mTLS client keypair;
// storageLimit, when non-empty, caps this output's filesystem retry backlog.
func (c *fluentBitComponent) linseedHTTPOutput(tag, certPath, keyPath, storageLimit string) map[string]interface{} {
	host, port := splitEndpoint(relasticsearch.LinseedEndpoint(c.SupportedOSType(), c.cfg.ClusterDomain, render.LinseedNamespace(c.cfg.Tenant), c.cfg.ManagedCluster, true))
	out := map[string]interface{}{
		"name":   "http",
		"match":  tag,
		"host":   host,
		"port":   port,
		"uri":    linseedBulkURI(tag),
		"format": "json_lines",
		// One record per line, nothing else: Linseed parses each line as the
		// log document itself, so no synthetic date field is added.
		"json_date_key": false,
		"tls":           "on",
		"tls.verify":    "on",
		// tls.verify only checks the chain; hostname/SAN verification is a
		// separate knob that defaults off in fluent-bit. The Go plugin this
		// replaces verified hostnames (crypto/tls default), so keep parity.
		"tls.verify_hostname": "on",
		"tls.ca_file":         c.trustedBundlePath(),
		"tls.crt_file":        certPath,
		"tls.key_file":        keyPath,
		"bearer_token_file":   c.path(render.GetLinseedTokenPath(c.cfg.ManagedCluster)),
		// Retry failed chunks until they send instead of dropping them after
		// the default single retry; the filesystem storage bounds what can
		// accumulate during a Linseed outage.
		"retry_limit": "no_limits",
	}
	if storageLimit != "" {
		out["storage.total_limit_size"] = storageLimit
	}
	if c.cfg.Tenant != nil && c.cfg.ExternalElastic {
		out["header"] = fmt.Sprintf("x-tenant-id %s", c.cfg.Tenant.Spec.ID)
	}
	return out
}

// linseedStorageLimit sizes a tag's filesystem retry backlog: flow logs are
// the dominant volume and keep the budget the single shared output used to
// have; everything else is low-volume.
func linseedStorageLimit(tag string) string {
	if tag == "flows" || tag == "non_cluster_flows" {
		return "500M"
	}
	return "100M"
}

func (c *fluentBitComponent) renderFluentBitConf() string {
	caPath := c.trustedBundlePath()
	keyPath := c.keyPath()
	certPath := c.certPath()

	cfg := fluentBitConfig{
		Service: map[string]interface{}{
			"flush":       5,
			"log_level":   "info",
			"http_server": true,
			"http_port":   FluentBitMetricsPort,
			// Enable the /api/v1/health endpoint that the liveness/readiness/
			// startup probes hit (without this it returns 404 and pods never
			// become Ready).
			"health_check": true,
			// Filesystem buffering under the same hostPath-backed state dir as
			// the tail offset DBs, so buffered-but-unsent chunks survive pod
			// restarts (fluentd buffered to disk for up to 72h).
			"storage.path": c.path("/var/log/calico/calico-fluent-bit/storage"),
		},
		// Parsers referenced by the tail inputs. Defined inline so the config is
		// self-contained and does not depend on the image's parsers.conf.
		Parsers: []map[string]interface{}{
			{"name": "json", "format": "json"},
			// Audit events carry their event time in the `time` key; parse it so
			// time-partitioned sinks (S3 day keys, syslog timestamps) use event
			// time, matching fluentd's `time_key time` on the audit sources. Like
			// fluentd (no keep_time_key), the key is consumed by the parser.
			{"name": "json_audit", "format": "json", "time_key": "time", "time_format": "%Y-%m-%dT%H:%M:%S.%L%z"},
			// IDS events carry a unix-seconds `time` key; fluentd parsed it with
			// `time_type unixtime` and kept the key in the record.
			{"name": "json_ids_events", "format": "json", "time_key": "time", "time_format": "%s", "time_keep": true},
			{"name": "bird_regex", "format": "regex", "regex": `^(?<logtime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d{5} bird: (?<message>.*)`},
		},
	}

	for _, in := range c.logInputs() {
		cfg.Pipeline.Inputs = append(cfg.Pipeline.Inputs, map[string]interface{}{
			"name": "tail",
			"path": c.path(in.path),
			"tag":  in.tag,
			// Persist read offsets in SQLite under /var/log/calico/calico-fluent-bit
			// — the same directory the host rpm/deb package uses, and a subdir of the
			// already-mounted var-log-calico volume — so the tail resumes across
			// restarts instead of re-shipping from the head. The pos-migrator init
			// container seeds these DBs from the legacy fluentd .pos files at cutover;
			// read_from_head only applies to files with no prior offset (first install).
			"db":             c.path(fmt.Sprintf("/var/log/calico/calico-fluent-bit/in_tail_%s.db", in.tag)),
			"parser":         in.parser,
			"read_from_head": true,
			"storage.type":   "filesystem",
		})
	}

	if c.cfg.NonClusterHost != nil && c.cfg.OSType == rmeta.OSTypeLinux {
		cfg.Pipeline.Inputs = append(cfg.Pipeline.Inputs, map[string]interface{}{
			"name":         "http",
			"listen":       "0.0.0.0",
			"port":         FluentBitInputPort,
			"tls":          "on",
			"tls.ca_file":  caPath,
			"tls.crt_file": certPath,
			"tls.key_file": keyPath,
			// Require a Tigera-CA-signed client certificate, like fluentd's http
			// source did (client_cert_auth true) — voltron presents its internal
			// client certificate on this hop.
			"tls.verify_client_cert": "on",
			"storage.type":           "filesystem",
		})
	}

	// Per-log-type transforms (host injection, flows @timestamp, audit name
	// derivation, BIRD ip_version + noise drop, etc.) are implemented in the
	// record_transformer.lua filter shipped in the image, keyed by tag.
	cfg.Pipeline.Filters = append(cfg.Pipeline.Filters, map[string]interface{}{
		"name":   "lua",
		"match":  "*",
		"script": c.luaScriptPath(),
		"call":   "record_transformer",
	})

	// User-provided flow/dns filters (from the fluent-bit-filters ConfigMap) are
	// inlined into the pipeline, replacing fluentd's config-include mechanism.
	// Each ConfigMap key holds a YAML list of fluent-bit filter entries.
	c.addUserFilters(&cfg)

	// One built-in http output per Linseed-bound tag: chunks are per-tag, so
	// an exact match per block routes every record to its bulk endpoint. The
	// per-tag split replaces the single out_linseed Go proxy output — the C
	// http output keeps the container free of Go proxy plugins.
	for _, tag := range c.linseedTags() {
		cfg.Pipeline.Outputs = append(cfg.Pipeline.Outputs,
			c.linseedHTTPOutput(tag, certPath, keyPath, linseedStorageLimit(tag)))
	}

	// Additional stores are Linux-only, matching the fluentd Windows variant
	// (Linseed only).
	if c.cfg.LogCollector.Spec.AdditionalStores != nil && c.cfg.OSType == rmeta.OSTypeLinux {
		c.addS3Outputs(&cfg)
		c.addSyslogOutputs(&cfg)
		c.addSplunkOutputs(&cfg)
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Sprintf("# error rendering config: %v\n", err)
	}
	return string(out)
}

func (c *fluentBitComponent) trustedBundlePath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return certificatemanagement.TrustedCertBundleMountPathWindows
	}
	return c.cfg.TrustedBundle.MountPath()
}

func (c *fluentBitComponent) keyPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return fmt.Sprintf("c:/%s/%s", c.cfg.FluentBitKeyPair.GetName(), corev1.TLSPrivateKeyKey)
	}
	return c.cfg.FluentBitKeyPair.VolumeMountKeyFilePath()
}

func (c *fluentBitComponent) certPath() string {
	if c.cfg.OSType == rmeta.OSTypeWindows {
		return fmt.Sprintf("c:/%s/%s", c.cfg.FluentBitKeyPair.GetName(), corev1.TLSCertKey)
	}
	return c.cfg.FluentBitKeyPair.VolumeMountCertificateFilePath()
}
