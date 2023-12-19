// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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
	"net/http"
	"time"

	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"

	"github.com/olivere/elastic/v7"

	operator "github.com/tigera/operator/api/v1"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

type policyDetail struct {
	rolloverAge  string
	rolloverSize string
	deleteAge    string
	policy       map[string]interface{}
}

type logrWrappedESLogger struct{}

func (l logrWrappedESLogger) Printf(format string, v ...interface{}) {
	log.Error(nil, fmt.Sprintf(format, v...))
}

// ElasticsearchSecrets gets the secrets needed for a component to be able to access Elasticsearch.
func ElasticsearchSecrets(ctx context.Context, userSecretNames []string, cli client.Client) ([]*corev1.Secret, error) {
	var esUserSecrets []*corev1.Secret
	for _, userSecretName := range userSecretNames {
		esUserSecret := &corev1.Secret{}
		err := cli.Get(ctx, types.NamespacedName{
			Name:      userSecretName,
			Namespace: common.OperatorNamespace(),
		}, esUserSecret)
		if err != nil {
			return nil, err
		}

		esUserSecrets = append(esUserSecrets, esUserSecret)
	}
	return esUserSecrets, nil
}

// GetElasticsearchClusterConfig retrieves the config map containing the elasticsearch configuration values, such as the
// the cluster name and replica count.
func GetElasticsearchClusterConfig(ctx context.Context, cli client.Client) (*relasticsearch.ClusterConfig, error) {
	configMap := &corev1.ConfigMap{}
	if err := cli.Get(ctx, client.ObjectKey{Name: relasticsearch.ClusterConfigConfigMapName, Namespace: common.OperatorNamespace()}, configMap); err != nil {
		return nil, err
	}

	return relasticsearch.NewClusterConfigFromConfigMap(configMap)
}

type ElasticsearchClientCreator func(client client.Client, ctx context.Context, elasticHTTPSEndpoint string) (ElasticClient, error)

type ElasticClient interface {
	SetILMPolicies(context.Context, *operatorv1.LogStorage) error
	CreateUser(context.Context, *User) error
	DeleteUser(context.Context, *User) error
	GetUsers(ctx context.Context) ([]User, error)
}

type esClient struct {
	client *elastic.Client
}

func NewElasticClient(client client.Client, ctx context.Context, elasticHTTPSEndpoint string) (ElasticClient, error) {
	user, password, root, err := getClientCredentials(client, ctx)
	if err != nil {
		return nil, err
	}
	h := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: root}},
	}

	options := []elastic.ClientOptionFunc{
		elastic.SetURL(elasticHTTPSEndpoint),
		elastic.SetHttpClient(h),
		elastic.SetErrorLog(logrWrappedESLogger{}),
		elastic.SetSniff(false),
		elastic.SetHealthcheck(false),
		elastic.SetBasicAuth(user, password),
	}
	retryInterval, err := time.ParseDuration(ElasticConnRetryInterval)
	if err != nil {
		return nil, err
	}

	var esCli *elastic.Client
	for i := 0; i < ElasticConnRetries; i++ {
		esCli, err = elastic.NewClient(options...)
		if err == nil {
			break
		}
		log.Error(err, "Elastic connect failed, retrying")
		time.Sleep(retryInterval)
	}

	return &esClient{client: esCli}, err
}

func formatName(name, clusterID, tenantID string) string {
	return fmt.Sprintf("%s_%s_%s", name, clusterID, tenantID)
}

func indexPattern(prefix, cluster, suffix, tenant string) string {
	if tenant != "" {
		return fmt.Sprintf("%s.%s.%s%s", prefix, tenant, cluster, suffix)
	}
	return fmt.Sprintf("%s.%s%s", prefix, cluster, suffix)
}

// Name for the linseed user in ES.
var ElasticsearchUserNameLinseed = "tigera-ee-linseed"

func LinseedUser(clusterID, tenant string) *User {
	username := formatName(ElasticsearchUserNameLinseed, clusterID, tenant)
	return &User{
		Username: username,
		Roles: []Role{
			{
				Name: username,
				Definition: &RoleDefinition{
					Cluster: []string{"monitor", "manage_index_templates", "manage_ilm"},
					Indices: []RoleIndex{
						{
							// Include both single-index and multi-index name formats.
							Names:      []string{indexPattern("tigera_secure_ee_*", "*", ".*", tenant), "calico_*"},
							Privileges: []string{"create_index", "write", "manage", "read"},
						},
					},
				},
			},
		},
	}
}

// User represents an Elasticsearch user, which may or may not have roles attached to it
type User struct {
	Username string
	Password string
	Roles    []Role
}

// RoleNames is a convenience function for getting the names of all the roles defined for this Elasticsearch user
func (u User) RoleNames() []string {
	// The Elasticsearch users API expects a string array in the "roles" field and will fail if it detects a null value
	// instead. Initialising the slice in this manner ensures that even in the case that there are no roles we still
	// send an empty array of strings rather than null.
	names := []string{}
	for _, role := range u.Roles {
		names = append(names, role.Name)
	}

	return names
}

// Role represents an Elasticsearch role that may be attached to a User
type Role struct {
	Name       string `json:"-"`
	Definition *RoleDefinition
}

type RoleDefinition struct {
	Cluster      []string      `json:"cluster"`
	Indices      []RoleIndex   `json:"indices"`
	Applications []Application `json:"applications,omitempty"`
}

type RoleIndex struct {
	Names      []string `json:"names"`
	Privileges []string `json:"privileges"`
}

type Application struct {
	Application string   `json:"application"`
	Privileges  []string `json:"privileges"`
	Resources   []string `json:"resources"`
}

// CreateRoles wraps createRoles to make creating multiple rows slightly more convenient
func (es *esClient) CreateRoles(ctx context.Context, roles ...Role) error {
	for _, role := range roles {
		if err := es.createRole(ctx, role); err != nil {
			return err
		}
	}

	return nil
}

// createRole attempts to create (or updated) the given Elasticsearch role.
func (es *esClient) createRole(ctx context.Context, role Role) error {
	if role.Name == "" {
		return fmt.Errorf("can't create a role with an empty name")
	}

	_, err := es.client.XPackSecurityPutRole(role.Name).Body(role.Definition).Do(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (es *esClient) CreateUser(ctx context.Context, user *User) error {
	var rolesToCreate []Role
	for _, role := range user.Roles {
		if role.Definition != nil {
			rolesToCreate = append(rolesToCreate, role)
		}
	}

	if len(rolesToCreate) > 0 {
		if err := es.CreateRoles(ctx, rolesToCreate...); err != nil {
			return err
		}
	}

	body := map[string]interface{}{
		"password": user.Password,
		"roles":    user.RoleNames(),
	}

	_, err := es.client.XPackSecurityPutUser(user.Username).Body(body).Do(ctx)
	if err != nil {
		log.Error(err, "Error creating user")
		return err
	}

	return nil
}

// DeleteRoles wraps deleteRoles to make deleting multiple rows slightly more convenient
func (es *esClient) DeleteRoles(ctx context.Context, roles []Role) error {
	for _, role := range roles {
		if err := es.deleteRole(ctx, role); err != nil {
			return err
		}
	}

	return nil
}

// deleteRole attempts to delete the given Elasticsearch role.
func (es *esClient) deleteRole(ctx context.Context, role Role) error {
	if role.Name == "" {
		return fmt.Errorf("can't delete a role with an empty name")
	}

	_, err := es.client.XPackSecurityDeleteRole(role.Name).Do(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (es *esClient) DeleteUser(ctx context.Context, user *User) error {
	if err := es.DeleteRoles(ctx, user.Roles); err != nil {
		return err
	}

	_, err := es.client.XPackSecurityDeleteUser(user.Username).Do(ctx)
	if err != nil {
		log.Error(err, "Error deleting user")
		return err
	}

	return nil
}

// GetUsers returns all users stored in ES
func (es *esClient) GetUsers(ctx context.Context) ([]User, error) {
	usersResponse, err := es.client.XPackSecurityGetUser("").Do(ctx)
	if err != nil {
		log.Error(err, "Error getting users")
		return []User{}, err
	}

	users := []User{}
	for name, data := range *usersResponse {
		user := User{
			Username: name,
		}
		for _, roleName := range data.Roles {
			role := Role{
				Name: roleName,
			}
			user.Roles = append(user.Roles, role)
		}
		users = append(users, user)
	}

	return users, nil
}

// SetILMPolicies creates ILM policies for each timeseries based index using the retention period and storage size in LogStorage
func (es *esClient) SetILMPolicies(ctx context.Context, ls *operatorv1.LogStorage) error {
	policyList := es.listILMPolicies(ls)
	return es.createOrUpdatePolicies(ctx, policyList)
}

// listILMPolicies generates ILM policies based on disk space and retention in LogStorage
// Allocate 70% of ES disk space to flows, dns and bgp logs [majorPctOfTotalDisk]
// Allocate 90% of the 70% ES disk space to flow logs, 5% of the 70% ES disk space to each dns and bgp logs.
// Allocate 10% of ES disk space to logs that are NOT flows, dns or bgp [minorPctOfTotalDisk]
// Equally distribute 10% of the ES disk space among these other log types
func (es *esClient) listILMPolicies(ls *operatorv1.LogStorage) map[string]policyDetail {
	totalEsStorage := getTotalEsDisk(ls)
	majorPctOfTotalDisk := 0.7

	// numOfIndicesWithMinorSpace is the number of time series indices created that are not flows, dns or bgp related.
	// i.e., audit_ee, audit_kube, compliance_reports, benchmark_results, events, snapshots
	numOfIndicesWithMinorSpace := 6
	minorPctOfTotalDisk := 0.1
	pctOfDisk := minorPctOfTotalDisk / float64(numOfIndicesWithMinorSpace)

	// Retention is not set in LogStorage for l7, benchmark and events logs
	return map[string]policyDetail{
		"tigera_secure_ee_flows": buildILMPolicy(totalEsStorage, majorPctOfTotalDisk, 0.85, int(*ls.Spec.Retention.Flows)),
		"tigera_secure_ee_dns":   buildILMPolicy(totalEsStorage, majorPctOfTotalDisk, 0.05, int(*ls.Spec.Retention.DNSLogs)),
		"tigera_secure_ee_bgp":   buildILMPolicy(totalEsStorage, majorPctOfTotalDisk, 0.05, int(*ls.Spec.Retention.BGPLogs)),
		"tigera_secure_ee_l7":    buildILMPolicy(totalEsStorage, majorPctOfTotalDisk, 0.05, 1),

		"tigera_secure_ee_audit_ee":           buildILMPolicy(totalEsStorage, minorPctOfTotalDisk, pctOfDisk, int(*ls.Spec.Retention.AuditReports)),
		"tigera_secure_ee_audit_kube":         buildILMPolicy(totalEsStorage, minorPctOfTotalDisk, pctOfDisk, int(*ls.Spec.Retention.AuditReports)),
		"tigera_secure_ee_snapshots":          buildILMPolicy(totalEsStorage, minorPctOfTotalDisk, pctOfDisk, int(*ls.Spec.Retention.Snapshots)),
		"tigera_secure_ee_compliance_reports": buildILMPolicy(totalEsStorage, minorPctOfTotalDisk, pctOfDisk, int(*ls.Spec.Retention.ComplianceReports)),
		"tigera_secure_ee_benchmark_results":  buildILMPolicy(totalEsStorage, minorPctOfTotalDisk, pctOfDisk, 91),
		"tigera_secure_ee_events":             buildILMPolicy(totalEsStorage, minorPctOfTotalDisk, pctOfDisk, 91),
	}
}

func (es *esClient) createOrUpdatePolicies(ctx context.Context, listPolicy map[string]policyDetail) error {
	for indexName, pd := range listPolicy {
		policyName := indexName + "_policy"

		res, err := es.client.XPackIlmGetLifecycle().Policy(policyName).Do(ctx)
		if err != nil {
			if elastic.IsNotFound(err) {
				// If policy doesn't exist, create one
				return applyILMPolicy(ctx, es.client, indexName, pd.policy)
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
			return applyILMPolicy(ctx, es.client, indexName, pd.policy)
		}
	}
	return nil
}

func buildILMPolicy(totalEsStorage int64, totalDiskPercentage float64, percentOfDiskForLogType float64, retention int) policyDetail {
	pd := policyDetail{}
	pd.rolloverSize = calculateRolloverSize(totalEsStorage, totalDiskPercentage, percentOfDiskForLogType)
	pd.rolloverAge = calculateRolloverAge(retention)
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

func applyILMPolicy(ctx context.Context, esClient *elastic.Client, indexName string, policy map[string]interface{}) error {
	policyName := indexName + "_policy"
	_, err := esClient.XPackIlmPutLifecycle().Policy(policyName).BodyJson(policy).Do(ctx)
	if err != nil {
		log.Error(err, "Error applying Ilm Policy")
		return err
	}
	return nil
}

// calculateRolloverSize returns max_size to rollover
// max_size is based on the disk space allocated for the log type divided by ElasticsearchRetentionFactor
// If calculated max_size is greater than ES recommended shard size (DefaultMaxIndexSizeGi), set it to DefaultMaxIndexSizeGi
func calculateRolloverSize(totalEsStorage int64, diskPercentage float64, diskForLogType float64) string {
	rolloverSize := int64((float64(totalEsStorage) * diskPercentage * diskForLogType) / ElasticsearchRetentionFactor)
	rolloverMax := resource.MustParse(fmt.Sprintf("%dGi", DefaultMaxIndexSizeGi))
	maxRolloverSize := rolloverMax.Value()

	if rolloverSize > maxRolloverSize {
		rolloverSize = maxRolloverSize
	}

	return fmt.Sprintf("%db", rolloverSize)
}

// calculateRolloverAge returns max_age to rollover
// max_age to rollover an index is retention period set in LogStorage divided by ElasticsearchRetentionFactor
// If retention is < ElasticsearchRetentionFactor, set rollover age to 1 day
// if retention is 0 days, rollover every 1 hr - we dont want to rollover index every few ms/s set it to 1hr
func calculateRolloverAge(retention int) string {
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

// getClientCredentials gets the client credentials used by the operator to talk to Elasticsearch. The operator
// uses the ES admin credentials in order to provision users and ILM policies.
func getClientCredentials(client client.Client, ctx context.Context) (string, string, *x509.CertPool, error) {
	esSecret := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchAdminUserSecret, Namespace: common.OperatorNamespace()}, esSecret); err != nil {
		return "", "", nil, err
	}

	// Extract the password from the secret. The username is always "elastic".
	username := "elastic"
	password := string(esSecret.Data[username])

	// Determine the CA to use for validating the Elasticsearch server certificate.
	roots, err := getESRoots(ctx, client)
	if err != nil {
		return "", "", nil, err
	}

	return username, password, roots, nil
}

// getESRoots returns the root certificates used to validate the Elasticsearch server certificate.
func getESRoots(ctx context.Context, client client.Client) (*x509.CertPool, error) {
	instance := &operator.Installation{}
	if err := client.Get(ctx, DefaultInstanceKey, instance); err != nil {
		return nil, err
	}

	// Determine the CA to use for validating the Elasticsearch server certificate.
	var caPEM []byte
	if instance.Spec.CertificateManagement != nil {
		// If certificate managemement is enabled, use the provided CA.
		caPEM = instance.Spec.CertificateManagement.CACert
	} else {
		// Otherwise, load the CA from the Elasticsearch internal cert secret.
		esPublicCert := &corev1.Secret{}
		if err := client.Get(ctx, types.NamespacedName{Name: render.TigeraElasticsearchInternalCertSecret, Namespace: common.OperatorNamespace()}, esPublicCert); err != nil {
			return nil, err
		}
		var exists bool
		caPEM, exists = esPublicCert.Data["tls.crt"]
		if !exists {
			return nil, fmt.Errorf("couldn't find tls.crt in Elasticsearch secret")
		}
	}

	// Build a cert pool using the CA.
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(caPEM)
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
	totalEsStorage := defaultStorage.Value()
	if ls.Spec.Nodes.ResourceRequirements != nil {
		if val, ok := ls.Spec.Nodes.ResourceRequirements.Requests["storage"]; ok {
			totalEsStorage = val.Value()
		}
	}
	return totalEsStorage
}
