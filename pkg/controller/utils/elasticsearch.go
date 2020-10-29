// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

// This file contains functions common to the controllers to help them interact with elasticsearch.
package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"net/http"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

const (
	// NumOfIndexNotFlowsDnsBgp is the number of index created that are not flows, dns or bgp.
	NumOfIndexNotFlowsDnsBgp = 6
	// diskDistribution is % of disk to be allocated for log types other than flows, dns and bgp.
	diskDistribution             = 0.1 / NumOfIndexNotFlowsDnsBgp
	ElasticsearchRetentionFactor = 4
	DefaultMaxIndexSizeGi        = 30
	ElasticConnRetries           = 10
	ElasticConnRetryInterval     = "500ms"
)

type IndexDiskAllocation struct {
	TotalDiskPercentage float64
	IndexNameSize       map[string]float64
}

type Policy struct {
	Phases struct {
		Hot struct {
			Actions struct {
				Rollover struct {
					MaxSize string `json:"max_size"`
					MaxAge  string `json:"max_age"`
				}
			}
		}
		Delete struct {
			MinAge string `json:"min_age"`
		}
	}
}

// IndexDiskMapping gives disk allocation for each log type.
// Allocate 70% of ES disk space to flows, dns and bgp logs and 10% disk space to remaining log types.
// Allocate 90% of the 70% ES disk space to flow logs, 5% of the 70% ES disk space to each dns and bgp logs
// Equally distribute 10% ES disk space among all the other logs
var IndexDiskMapping = []IndexDiskAllocation{
	{
		TotalDiskPercentage: 0.7,
		IndexNameSize: map[string]float64{
			"tigera_secure_ee_flows": 0.9,
			"tigera_secure_ee_dns":   0.05,
			"tigera_secure_ee_bgp":   0.05,
		},
	},
	{
		TotalDiskPercentage: 0.1,
		IndexNameSize: map[string]float64{
			"tigera_secure_ee_audit_ee":           diskDistribution,
			"tigera_secure_ee_audit_kube":         diskDistribution,
			"tigera_secure_ee_snapshots":          diskDistribution,
			"tigera_secure_ee_benchmark_results":  diskDistribution,
			"tigera_secure_ee_compliance_reports": diskDistribution,
			"tigera_secure_ee_events":             diskDistribution,
		},
	},
}

// ElasticsearchSecrets gets the secrets needed for a component to be able to access Elasticsearch
func ElasticsearchSecrets(ctx context.Context, userSecretNames []string, cli client.Client) ([]*corev1.Secret, error) {
	var esUserSecrets []*corev1.Secret
	for _, userSecretName := range userSecretNames {
		esUserSecret := &corev1.Secret{}
		err := cli.Get(ctx, types.NamespacedName{
			Name:      userSecretName,
			Namespace: render.OperatorNamespace(),
		}, esUserSecret)
		if err != nil {
			return nil, err
		}

		esUserSecrets = append(esUserSecrets, esUserSecret)
	}

	esCertSecret := &corev1.Secret{}
	err := cli.Get(ctx, types.NamespacedName{
		Name:      render.ElasticsearchPublicCertSecret,
		Namespace: render.OperatorNamespace(),
	}, esCertSecret)
	if err != nil {
		return nil, err
	}

	return append(esUserSecrets, esCertSecret), nil
}

// GetElasticsearchClusterConfig retrieves the config map containing the elasticsearch configuration values, such as the
// the cluster name and replica count.
func GetElasticsearchClusterConfig(ctx context.Context, cli client.Client) (*render.ElasticsearchClusterConfig, error) {
	configMap := &corev1.ConfigMap{}
	if err := cli.Get(ctx, client.ObjectKey{Name: render.ElasticsearchConfigMapName, Namespace: render.OperatorNamespace()}, configMap); err != nil {
		return nil, err
	}

	return render.NewElasticsearchClusterConfigFromConfigMap(configMap)
}

type ElasticClient interface {
	NewElasticsearchClient(client.Client, context.Context) error
	SetElasticsearchIndices(context.Context, *operatorv1.LogStorage, int64) error
	GetElasticsearchClient() *elastic.Client
}

type EsClient struct {
	client *elastic.Client
}

func (es *EsClient) NewElasticsearchClient(client client.Client, ctx context.Context) error {
	user, password, root, err := getClientCredentials(client, ctx)
	if err != nil {
		return err
	}

	h := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: root}},
	}

	esClient, err := NewElastic(user, password, render.ElasticsearchHTTPSEndpoint, h)
	if err != nil {
		return err
	}
	es.client = esClient
	return nil
}

func (es *EsClient) SetElasticsearchIndices(ctx context.Context, ls *operatorv1.LogStorage, totalEsStorage int64) error {

	for _, v := range IndexDiskMapping {
		for indexName, p := range v.IndexNameSize {
			var retention int
			switch indexName {
			case "tigera_secure_ee_flows":
				retention = int(*ls.Spec.Retention.Flows)
			case "tigera_secure_ee_audit_ee", "tigera_secure_ee_audit_kube":
				retention = int(*ls.Spec.Retention.AuditReports)
			case "tigera_secure_ee_snapshots":
				retention = int(*ls.Spec.Retention.Snapshots)
			case "tigera_secure_ee_compliance_reports":
				retention = int(*ls.Spec.Retention.ComplianceReports)
			case "tigera_secure_ee_benchmark_results", "tigera_secure_ee_events":
				retention = 91
			case "tigera_secure_ee_dns", "tigera_secure_ee_bgp":
				retention = 8
			}

			rolloverSize := CalculateRolloverSize(totalEsStorage, v.TotalDiskPercentage, p)
			rolloverAge := CalculateRolloverAge(retention)

			if err := BuildAndApplyIlmPolicy(ctx, es.client, retention, rolloverSize, rolloverAge, indexName); err != nil {
				return err
			}
		}
	}
	return nil
}

func (es *EsClient) GetElasticsearchClient() *elastic.Client {
	return es.client
}

func NewElastic(user, password, url string, h *http.Client) (*elastic.Client, error) {

	options := []elastic.ClientOptionFunc{
		elastic.SetURL(url),
		elastic.SetHttpClient(h),
		elastic.SetErrorLog(logrus.StandardLogger()),
		elastic.SetSniff(false),
		//elastic.SetTraceLog(logrus.StandardLogger()),
		elastic.SetBasicAuth(user, password),
	}

	retryInterval, err := time.ParseDuration(ElasticConnRetryInterval)
	if err != nil {
		return nil, err
	}

	var eserr error
	var esClient *elastic.Client
	for i := 0; i < ElasticConnRetries; i++ {

		esClient, eserr = elastic.NewClient(options...)
		if eserr == nil {
			return esClient, nil
		}
		log.Error(err, "Elastic connect failed, retrying")
		time.Sleep(retryInterval)
	}
	return nil, eserr
}

func CalculateRolloverSize(totalEsStorage int64, diskPercentage float64, diskForLogType float64) string {
	rolloverSize := int64((float64(totalEsStorage) * diskPercentage * diskForLogType) / ElasticsearchRetentionFactor)
	rolloverMax := resource.MustParse(fmt.Sprintf("%dGi", DefaultMaxIndexSizeGi))
	maxRolloverSize := rolloverMax.Value()

	if rolloverSize > maxRolloverSize {
		rolloverSize = maxRolloverSize
	}

	return fmt.Sprintf("%db", rolloverSize)
}

func CalculateRolloverAge(retention int) string {
	var age string
	// if retention(say 3d) is < ElasticsearchRetentionFactor, set rollover age to 1 day
	// if retention is 0 days, rollover every 1 hr - we dont want to rollover index every few ms/s set it to 1hr similar to es-curator cronjob interval
	if retention <= 0 {
		age = "1h"
	} else if retention < ElasticsearchRetentionFactor {
		age = "1d"
	} else {
		rolloverAge := retention / ElasticsearchRetentionFactor
		age = fmt.Sprintf("%dd", rolloverAge)
	}
	return age
}

func getClientCredentials(client client.Client, ctx context.Context) (string, string, *x509.CertPool, error) {
	esSecret := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchOperatorUserSecret, Namespace: render.OperatorNamespace()}, esSecret); err != nil {
		if !errors.IsNotFound(err) {
			return "", "", nil, err
		}
		log.Info("Elasticsearch public cert secret not found yet")
	}

	esPublicCert := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchPublicCertSecret, Namespace: render.OperatorNamespace()}, esPublicCert); err != nil {
		return "", "", nil, err
	}

	roots, err := getESRoots(esPublicCert)
	return string(esSecret.Data["username"]), string(esSecret.Data["password"]), roots, err
}

func getESRoots(esCertSecret *corev1.Secret) (*x509.CertPool, error) {
	rootPEM, exists := esCertSecret.Data["tls.crt"]
	if !exists {
		return nil, fmt.Errorf("couldn't find tls.crt in Elasticsearch secret")
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		return nil, fmt.Errorf("failed to parse root certificate")
	}

	return roots, nil
}

func BuildAndApplyIlmPolicy(ctx context.Context, esClient *elastic.Client, retention int, rolloverSize string, rolloverAge string, name string) error {
	policyName := name + "_policy"

	rollover := map[string]interface{}{
		"max_size": rolloverSize,
		"max_age":  rolloverAge,
	}
	minRetentionAge := fmt.Sprintf("%dd", retention)

	newIlmPolicy := buildIlmPolicy(rollover, minRetentionAge)

	res, err := esClient.XPackIlmGetLifecycle().Policy(policyName).Do(ctx)
	if err != nil {
		if eerr, ok := err.(*elastic.Error); ok && eerr.Status == 404 {
			// If policy doesn't exist, create one
			return applyIlmPolicy(ctx, esClient, name, newIlmPolicy)
		}
		return err
	}

	// If policy exists, check if needs to be updated
	currentMaxAge, currentMaxSize, currentMinAge, err := extractPolicyDetails(res[policyName].Policy)
	if err != nil {
		return err
	}
	if currentMaxAge != rollover["max_age"] || currentMaxSize != rollover["max_size"] || currentMinAge != minRetentionAge {
		return applyIlmPolicy(ctx, esClient, name, newIlmPolicy)
	}
	// if there is an existing policy with latest retention, do nothing
	return nil
}

func buildIlmPolicy(rollover map[string]interface{}, minRetentionAge string) map[string]interface{} {
	hotPriority := map[string]interface{}{
		"priority": 100,
	}
	hotAction := make(map[string]interface{})
	hotAction["rollover"] = rollover
	hotAction["set_priority"] = hotPriority

	warmPriority := map[string]interface{}{
		"priority": 50,
	}
	warmAction := make(map[string]interface{})
	warmAction["readonly"] = make(map[string]interface{})
	warmAction["set_priority"] = warmPriority

	deleteAction := make(map[string]interface{})
	deleteAction["delete"] = make(map[string]interface{})

	newPolicy := make(map[string]interface{})
	newPolicy["policy"] = map[string]interface{}{
		"phases": map[string]interface{}{
			"hot": map[string]interface{}{
				"actions": hotAction,
			},
			"warm": map[string]interface{}{
				"actions": warmAction,
			},
			"delete": map[string]interface{}{
				"min_age": minRetentionAge,
				"actions": deleteAction,
			},
		},
	}
	return newPolicy
}

func applyIlmPolicy(ctx context.Context, esClient *elastic.Client, indexName string, policy map[string]interface{}) error {

	policyName := indexName + "_policy"
	_, err := esClient.XPackIlmPutLifecycle().Policy(policyName).BodyJson(policy).Do(ctx)
	if err != nil {
		log.Error(err, "Error applying Ilm Policy")
		return err
	}

	return nil
}

func extractPolicyDetails(policy map[string]interface{}) (string, string, string, error) {
	jsonPolicy, err := json.Marshal(policy)
	if err != nil {
		return "", "", "", err
	}
	existingPolicy := Policy{}
	if err = json.Unmarshal(jsonPolicy, &existingPolicy); err != nil {
		return "", "", "", err
	}

	currentMaxAge := existingPolicy.Phases.Hot.Actions.Rollover.MaxAge
	currentMaxSize := existingPolicy.Phases.Hot.Actions.Rollover.MaxSize
	currentMinAge := existingPolicy.Phases.Delete.MinAge
	return currentMaxAge, currentMaxSize, currentMinAge, nil

}
