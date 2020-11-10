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
	ElasticsearchRetentionFactor = 4
	DefaultMaxIndexSizeGi        = 30
	ElasticConnRetries           = 10
	ElasticConnRetryInterval     = "500ms"
)

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

type PolicyDetail struct {
	rolloverAge  string
	rolloverSize string
	deleteAge    string
	policy       map[string]interface{}
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
	SetILMPolicies(*operatorv1.LogStorage) error
	GetClient() *elastic.Client
}

type EsClient struct {
	Ctx    context.Context
	Client *elastic.Client
}

// GetElasticClient creates new Elastic client and returns ElasticClient interface
func GetElasticClient(client client.Client, ctx context.Context) (ElasticClient, error) {
	esClnt, err := NewClient(client, ctx)
	if err != nil {
		return nil, err
	}
	es := EsClient{ctx, esClnt}
	return &es, nil
}

// SetILMPolicies creates ILM policies for each timeseries based index using the retention period and storage size in LogStorage
func (es *EsClient) SetILMPolicies(ls *operatorv1.LogStorage) error {
	policyList := es.ListILMPolicies(ls)
	return es.CreateOrUpdatePolicies(policyList)
}

func (es *EsClient) ListILMPolicies(ls *operatorv1.LogStorage) map[string]PolicyDetail {
	totalEsStorage := getTotalEsDisk(ls)

	listPolicy := make(map[string]PolicyDetail)
	listPolicy = policiesForIndicesWithMajorSpace(listPolicy, totalEsStorage, ls)
	listPolicy = policiesForIndicesWithMinorSpace(listPolicy, totalEsStorage, ls)
	return listPolicy
}

func (es *EsClient) CreateOrUpdatePolicies(listPolicy map[string]PolicyDetail) error {
	for indexName, pd := range listPolicy {
		policyName := indexName + "_policy"

		res, err := es.Client.XPackIlmGetLifecycle().Policy(policyName).Do(es.Ctx)
		if err != nil {
			if eerr, ok := err.(*elastic.Error); ok && eerr.Status == 404 {
				// If policy doesn't exist, create one
				return ApplyIlmPolicy(es.Ctx, es.Client, indexName, pd.policy)
			}
			return err
		}

		// If policy exists, check if it needs to be updated
		currentMaxAge, currentMaxSize, currentMinAge, err := extractPolicyDetails(res[policyName].Policy)
		if err != nil {
			return err
		}
		if currentMaxAge != pd.rolloverAge ||
			currentMaxSize != pd.rolloverSize ||
			currentMinAge != pd.deleteAge {
			return ApplyIlmPolicy(es.Ctx, es.Client, indexName, pd.policy)
		}
	}
	return nil
}

func (es *EsClient) GetClient() *elastic.Client {
	return es.Client
}

func NewClient(client client.Client, ctx context.Context) (*elastic.Client, error) {
	user, password, root, err := getClientCredentials(client, ctx)
	if err != nil {
		return nil, err
	}

	h := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: root}},
	}

	esClient, err := NewElastic(user, password, render.ElasticsearchHTTPSEndpoint, h)
	if err != nil {
		return nil, err
	}

	return esClient, nil
}

// policiesForIndicesWithMajorSpace returns PolicyDetail for ES index that consumes majority of disk
// 70% of ES disk space is allocated to flows, dns and bgp logs
// Allocate 90% of the 70% ES disk space to flow logs, 5% of the 70% ES disk space to each dns and bgp logs.
func policiesForIndicesWithMajorSpace(listPolicy map[string]PolicyDetail, totalEsStorage int64, ls *operatorv1.LogStorage) map[string]PolicyDetail {
	pctOfTotalDisk := 0.7
	diskAllocation := map[string]float64{
		"tigera_secure_ee_flows": 0.9,
		"tigera_secure_ee_dns":   0.05,
		"tigera_secure_ee_bgp":   0.05,
	}

	for indexName, pct := range diskAllocation {
		var retention int
		switch indexName {
		case "tigera_secure_ee_flows":
			retention = int(*ls.Spec.Retention.Flows)
		case "tigera_secure_ee_dns", "tigera_secure_ee_bgp":
			// There is no option to set retention for dns and bgp log in LogStorage, set default values used by curator
			retention = 8
		}

		pd := BuildIlmPolicy(totalEsStorage, pctOfTotalDisk, pct, retention)
		listPolicy[indexName] = pd
	}
	return listPolicy
}

// policiesForIndicesWithMinorSpace returns PolicyDetail for ES index that does not consumes majority of disk
// 10% of ES disk space is allocated to logs that are NOT flows, dns or bgp
// Equally distribute 10% of the ES disk space among other log types
func policiesForIndicesWithMinorSpace(listPolicy map[string]PolicyDetail, totalEsStorage int64, ls *operatorv1.LogStorage) map[string]PolicyDetail {
	// numOfIndicesWithMinorSpace is the number of time series indices created that are not flows, dns or bgp related.
	// i.e., audit_ee, audit_kube, compliance_reports, benchmark_results, events, snapshots
	numOfIndicesWithMinorSpace := 6
	pctOfTotalDisk := 0.1
	pctOfDisk := pctOfTotalDisk / float64(numOfIndicesWithMinorSpace)
	diskAllocationMinorLog := map[string]float64{
		"tigera_secure_ee_audit_ee":           pctOfDisk,
		"tigera_secure_ee_audit_kube":         pctOfDisk,
		"tigera_secure_ee_snapshots":          pctOfDisk,
		"tigera_secure_ee_benchmark_results":  pctOfDisk,
		"tigera_secure_ee_compliance_reports": pctOfDisk,
		"tigera_secure_ee_events":             pctOfDisk,
	}

	for indexName, pct := range diskAllocationMinorLog {
		var retention int
		switch indexName {
		case "tigera_secure_ee_audit_ee", "tigera_secure_ee_audit_kube":
			retention = int(*ls.Spec.Retention.AuditReports)
		case "tigera_secure_ee_snapshots":
			retention = int(*ls.Spec.Retention.Snapshots)
		case "tigera_secure_ee_compliance_reports":
			retention = int(*ls.Spec.Retention.ComplianceReports)
		case "tigera_secure_ee_benchmark_results", "tigera_secure_ee_events":
			// There is no option to set retention for benchmark and events log in LogStorage, set default values used by curator
			retention = 91
		}
		pd := BuildIlmPolicy(totalEsStorage, pctOfTotalDisk, pct, retention)
		listPolicy[indexName] = pd
	}
	return listPolicy
}

func BuildIlmPolicy(totalEsStorage int64, totalDiskPercentage float64, percentOfDiskForLogType float64, retention int) PolicyDetail {
	pd := PolicyDetail{}
	pd.rolloverSize = CalculateRolloverSize(totalEsStorage, totalDiskPercentage, percentOfDiskForLogType)
	pd.rolloverAge = CalculateRolloverAge(retention)
	pd.deleteAge = fmt.Sprintf("%dd", retention)

	pd.policy = map[string]interface{}{
		"policy": map[string]interface{}{
			"phases": map[string]interface{}{
				"hot": map[string]interface{}{
					"actions": map[string]interface{}{
						"rollover": map[string]interface{}{
							"max_size": pd.rolloverSize,
							"max_age":  pd.rolloverAge,
						},
						"set_priority": map[string]interface{}{
							"priority": 100,
						},
					},
				},
				"warm": map[string]interface{}{
					"actions": map[string]interface{}{
						"readonly": map[string]interface{}{},
						"set_priority": map[string]interface{}{
							"priority": 50,
						},
					},
				},
				"delete": map[string]interface{}{
					"min_age": pd.deleteAge,
					"actions": map[string]interface{}{
						"delete": map[string]interface{}{},
					},
				},
			},
		},
	}
	return pd
}

func ApplyIlmPolicy(ctx context.Context, esClient *elastic.Client, indexName string, policy map[string]interface{}) error {
	policyName := indexName + "_policy"
	_, err := esClient.XPackIlmPutLifecycle().Policy(policyName).BodyJson(policy).Do(ctx)
	if err != nil {
		log.Error(err, "Error applying Ilm Policy")
		return err
	}
	return nil
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

// CalculateRolloverSize returns max_size to rollover
// max_size is based on the disk space allocated for the log type divided by ElasticsearchRetentionFactor
// If calculated max_size is greater than ES recommended shard size (DefaultMaxIndexSizeGi), set it to DefaultMaxIndexSizeGi
func CalculateRolloverSize(totalEsStorage int64, diskPercentage float64, diskForLogType float64) string {
	rolloverSize := int64((float64(totalEsStorage) * diskPercentage * diskForLogType) / ElasticsearchRetentionFactor)
	rolloverMax := resource.MustParse(fmt.Sprintf("%dGi", DefaultMaxIndexSizeGi))
	maxRolloverSize := rolloverMax.Value()

	if rolloverSize > maxRolloverSize {
		rolloverSize = maxRolloverSize
	}

	return fmt.Sprintf("%db", rolloverSize)
}

// CalculateRolloverAge returns max_age to rollover
// max_age to rollover an index is retention period set in LogStorage divided by ElasticsearchRetentionFactor
// If retention is < ElasticsearchRetentionFactor, set rollover age to 1 day
// if retention is 0 days, rollover every 1 hr - we dont want to rollover index every few ms/s set it to 1hr similar to curator cronjob interval
func CalculateRolloverAge(retention int) string {
	var age string
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

func getTotalEsDisk(ls *operatorv1.LogStorage) int64 {
	defaultStorage := resource.MustParse(fmt.Sprintf("%dGi", render.DefaultElasticStorageGi))
	var totalEsStorage = defaultStorage.Value()
	if ls.Spec.Nodes.ResourceRequirements != nil {
		if val, ok := ls.Spec.Nodes.ResourceRequirements.Requests["storage"]; ok {
			totalEsStorage = val.Value()
		}
	}
	return totalEsStorage
}
