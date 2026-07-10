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
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

// renderFluentBitConf renders the fluent-bit configuration (in fluent-bit's
// YAML schema) that fluentBitConfigMap ships: the service and parser
// definitions, then the inputs → filters → outputs pipeline.
func (c *fluentBitComponent) renderFluentBitConf() string {
	cfg := fluentBitConfig{
		Service: map[string]interface{}{
			"flush":       5,
			"log_level":   "info",
			"http_server": true,
			"http_port":   FluentBitMetricsPort,
			// Enable the /api/v1/health endpoint the readiness probe hits
			// (without this it returns 404 and pods never become Ready).
			"health_check": true,
			// Filesystem buffering under the same hostPath-backed state dir as
			// the tail offset DBs, so buffered-but-unsent chunks survive pod
			// restarts — an improvement over fluentd, whose buffers were
			// memory-only (the on-disk pos file tracked what had been read,
			// not what had been delivered).
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

	c.addInputs(&cfg)
	c.addFilters(&cfg)
	c.addOutputs(&cfg)

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Sprintf("# error rendering config: %v\n", err)
	}
	return string(out)
}

// addInputs wires the tail inputs (one per log file) and, when non-cluster
// hosts are enabled, the HTTP input their logs arrive on.
func (c *fluentBitComponent) addInputs(cfg *fluentBitConfig) {
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
		// The ingress path for non-cluster-host log forwarding: voltron relays
		// the hosts' posts to this input, and in_http derives the
		// non_cluster_* tags from the request paths.
		cfg.Pipeline.Inputs = append(cfg.Pipeline.Inputs, map[string]interface{}{
			"name":   "http",
			"listen": "0.0.0.0",
			"port":   FluentBitInputPort,
			// fluentd's http source accepted bodies up to `body_size_limit
			// 100m`; in_http instead rejects anything over buffer_max_size
			// (default ~4M), so keep parity or large relayed batches are
			// silently dropped. buffer_chunk_size is the growth increment for
			// a connection's buffer (the 512K default would mean ~200
			// reallocations for a full-size post).
			"buffer_chunk_size": "5M",
			"buffer_max_size":   "100M",
			"tls":               "on",
			"tls.ca_file":       c.trustedBundlePath(),
			"tls.crt_file":      c.certPath(),
			"tls.key_file":      c.keyPath(),
			// Require a Tigera-CA-signed client certificate, like fluentd's http
			// source did (client_cert_auth true) — voltron presents its internal
			// client certificate on this hop.
			"tls.verify_client_cert": "on",
			"storage.type":           "filesystem",
		})
	}
}

// addFilters wires the record transforms and any user-provided filters
// between the inputs and the outputs.
func (c *fluentBitComponent) addFilters(cfg *fluentBitConfig) {
	// Per-log-type transforms (host injection, flows @timestamp, audit name
	// derivation, BIRD ip_version + noise drop) live in the image's
	// record_transformer.lua, keyed by tag. The same script also provides
	// syslog_pack, which the syslog outputs run as a per-output processor
	// (see addSyslogOutputs).
	cfg.Pipeline.Filters = append(cfg.Pipeline.Filters, map[string]interface{}{
		"name":   "lua",
		"match":  "*",
		"script": c.luaScriptPath(),
		"call":   "record_transformer",
	})

	// User-provided flow/dns filters: each fluent-bit-filters ConfigMap key
	// holds a YAML list of fluent-bit filter entries, inlined here.
	c.addUserFilters(cfg)
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
