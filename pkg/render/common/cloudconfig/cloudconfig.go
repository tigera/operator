// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudconfig

import (
	"fmt"
	"sort"
	"strconv"

	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CloudConfigConfigMapName = "tigera-secure-cloud-config"
)

// TenantOption customizes the Tenant that ToTenant returns.
type TenantOption func(*v1.Tenant)

// WithStandardIndices declares the standard single-index base names on the Tenant. Only clusters
// that have migrated to single-index storage should ask for them: index base names are otherwise
// left off the artificial single-tenant Tenant, and components fall back to their default names.
func WithStandardIndices() TenantOption {
	return func(tenant *v1.Tenant) {
		for dataType := range v1.DataTypes {
			tenant.Spec.Indices = append(tenant.Spec.Indices, v1.Index{DataType: dataType, BaseIndexName: cloudStandardIndices[dataType]})
		}

		// DataTypes is a map, so iteration order is random. Sort by data type to keep the generated
		// index list - and therefore the env vars rendered from it - stable across reconciles.
		sort.Slice(tenant.Spec.Indices, func(i, j int) bool {
			return tenant.Spec.Indices[i].DataType < tenant.Spec.Indices[j].DataType
		})
	}
}

// WithStandardIndicesIf applies WithStandardIndices only if useSingleIndex is set, for callers that
// carry that flag around as a bool.
func WithStandardIndicesIf(useSingleIndex bool) TenantOption {
	if !useSingleIndex {
		return func(*v1.Tenant) {}
	}
	return WithStandardIndices()
}

// cloudStandardIndices maps each data type to the standard index base name used by clusters that
// have migrated to single-index storage.
var cloudStandardIndices = map[v1.DataType]string{
	v1.DataTypeAlerts:               "calico_alerts_standard",
	v1.DataTypeAuditLogs:            "calico_auditlogs_standard",
	v1.DataTypeBGPLogs:              "calico_bgplogs_standard",
	v1.DataTypeComplianceBenchmarks: "calico_compliance_benchmarks_results_standard",
	v1.DataTypeComplianceReports:    "calico_compliance_reports_standard",
	v1.DataTypeComplianceSnapshots:  "calico_compliance_snapshots_standard",
	v1.DataTypeDNSLogs:              "calico_dnslogs_standard",
	v1.DataTypeFlowLogs:             "calico_flowlogs_standard",
	v1.DataTypeL7Logs:               "calico_l7logs_standard",
	v1.DataTypeRuntimeReports:       "calico_runtime_reports_standard",
	v1.DataTypeThreatFeedsDomainSet: "calico_threatfeeds_domainnameset_standard",
	v1.DataTypeThreatFeedsIPSet:     "calico_threatfeeds_ipset_standard",
	v1.DataTypeWAFLogs:              "calico_waflogs_standard",
	v1.DataTypePolicyActivity:       "calico_policy_activity_standard",
}

func NewCloudConfig(tenantId string, tenantName string, externalESDomain string, externalKibanaDomain string, enableMTLS bool) *CloudConfig {
	return &CloudConfig{
		tenantId:             tenantId,
		tenantName:           tenantName,
		externalESDomain:     externalESDomain,
		externalKibanaDomain: externalKibanaDomain,
		enableMTLS:           enableMTLS,
	}
}

func NewCloudConfigFromConfigMap(configMap *corev1.ConfigMap) (*CloudConfig, error) {
	var enableMTLS bool
	var err error

	if configMap.Data["tenantId"] == "" {
		return nil, fmt.Errorf("'tenantId' is not set")
	}

	if configMap.Data["tenantName"] == "" {
		return nil, fmt.Errorf("'tenantName' is not set")
	}

	if configMap.Data["externalESDomain"] == "" {
		return nil, fmt.Errorf("'externalESDomain' is not set")
	}

	if configMap.Data["externalKibanaDomain"] == "" {
		return nil, fmt.Errorf("'externalKibanaDomain' is not set")
	}

	if configMap.Data["enableMTLS"] == "" {
		enableMTLS = false
	} else {
		if enableMTLS, err = strconv.ParseBool(configMap.Data["enableMTLS"]); err != nil {
			return nil, errors.Wrap(err, "'enableMTLS' must be a bool")
		}
	}

	return NewCloudConfig(configMap.Data["tenantId"], configMap.Data["tenantName"], configMap.Data["externalESDomain"], configMap.Data["externalKibanaDomain"], enableMTLS), nil
}

type CloudConfig struct {
	tenantId             string
	tenantName           string
	externalESDomain     string
	externalKibanaDomain string
	enableMTLS           bool
}

// ToTenant converts the given CloudConfig structure to a Tenant object.
// This allows controllers that have been converted to support multi-tenancy to still leverage
// the single-tenant CloudConfig structure using the same code path as in multi-tenancy.
func (c CloudConfig) ToTenant(opts ...TenantOption) *v1.Tenant {
	tenant := &v1.Tenant{
		// We don't specify a Namespace for this tenant because it represents a singular tenant installed
		// in this management cluster. The signals to the render code that this is a single-tenant cluster and not
		// a cluster capable of multi-tenancy.
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec: v1.TenantSpec{
			ID:   c.tenantId,
			Name: c.tenantName,
			Elastic: &v1.TenantElasticSpec{
				URL:       fmt.Sprintf("https://%s:443", c.externalESDomain),
				KibanaURL: fmt.Sprintf("https://%s:443", c.externalKibanaDomain),
				MutualTLS: c.enableMTLS,
			},
		},
	}

	for _, opt := range opts {
		opt(tenant)
	}

	return tenant
}

func (c CloudConfig) TenantId() string {
	return c.tenantId
}

func (c CloudConfig) TenantName() string {
	return c.tenantName
}

func (c CloudConfig) ExternalESDomain() string {
	return c.externalESDomain
}

func (c CloudConfig) ExternalKibanaDomain() string {
	return c.externalKibanaDomain
}

func (c CloudConfig) EnableMTLS() bool {
	return c.enableMTLS
}

func (c CloudConfig) ConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CloudConfigConfigMapName,
			Namespace: common.OperatorNamespace(),
		},
		Data: map[string]string{
			"tenantId":             c.tenantId,
			"tenantName":           c.tenantName,
			"externalESDomain":     c.externalESDomain,
			"externalKibanaDomain": c.externalKibanaDomain,
			"enableMTLS":           strconv.FormatBool(c.enableMTLS),
		},
	}
}
