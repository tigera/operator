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

package render

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/elastic/cloud-on-k8s/pkg/utils/stringsutil"

	cmnv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/components"
	"gopkg.in/inf.v0"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	ECKOperatorName         = "elastic-operator"
	ECKOperatorNamespace    = "tigera-eck-operator"
	ECKWebhookSecretName    = "elastic-webhook-server-cert"
	ECKWebhookName          = "elastic-webhook-server"
	ECKEnterpriseTrial      = "eck-trial-license"
	ECKWebhookConfiguration = "elastic-webhook.k8s.elastic.co"

	ElasticsearchNamespace     = "tigera-elasticsearch"
	ElasticsearchHTTPURL       = "tigera-secure-es-http.tigera-elasticsearch.svc"
	ElasticsearchHTTPSEndpoint = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
	ElasticsearchName          = "tigera-secure"
	ElasticsearchConfigMapName = "tigera-secure-elasticsearch"
	ElasticsearchServiceName   = "tigera-secure-es-http"

	KibanaHTTPURL          = "tigera-secure-kb-http.tigera-kibana.svc"
	KibanaHTTPSEndpoint    = "https://tigera-secure-kb-http.tigera-kibana.svc:5601"
	KibanaName             = "tigera-secure"
	KibanaNamespace        = "tigera-kibana"
	KibanaPublicCertSecret = "tigera-secure-kb-http-certs-public"
	TigeraKibanaCertSecret = "tigera-secure-kibana-cert"
	KibanaDefaultCertPath  = "/etc/ssl/kibana/ca.pem"
	KibanaBasePath         = "tigera-kibana"
	KibanaServiceName      = "tigera-secure-kb-http"

	DefaultElasticsearchClusterName = "cluster"
	DefaultElasticsearchReplicas    = 0

	LogStorageFinalizer = "tigera.io/eck-cleanup"

	EsCuratorName = "elastic-curator"

	// As soon as the total disk utilization exceeds the max-total-storage-percent,
	// indices will be removed starting with the oldest. Picking a low value leads
	// to low disk utilization, while a high value might result in unexpected
	// behaviour.
	// Default: 80
	// +optional
	maxTotalStoragePercent int32 = 80

	// TSEE will remove dns and flow log indices once the combined data exceeds this
	// threshold. The default value (70% of the cluster size) is used because flow
	// logs and dns logs often use the most disk space; this allows compliance and
	// security indices to be retained longer. The oldest indices are removed first.
	// Set this value to be lower than or equal to, the value for
	// max-total-storage-pct.
	// Default: 70
	// +optional
	maxLogsStoragePercent int32 = 70
)

// Elasticsearch renders the
func LogStorage(
	logStorage *operatorv1.LogStorage,
	installation *operatorv1.Installation,
	elasticsearch *esv1.Elasticsearch,
	kibana *kbv1.Kibana,
	clusterConfig *ElasticsearchClusterConfig,
	elasticsearchSecrets []*corev1.Secret,
	kibanaSecrets []*corev1.Secret,
	createWebhookSecret bool,
	pullSecrets []*corev1.Secret,
	provider operatorv1.Provider,
	curatorSecrets []*corev1.Secret,
	esService *corev1.Service,
	kbService *corev1.Service,
	clusterDNS string,
	applyTrial bool) Component {

	return &elasticsearchComponent{
		logStorage:           logStorage,
		installation:         installation,
		elasticsearch:        elasticsearch,
		kibana:               kibana,
		clusterConfig:        clusterConfig,
		elasticsearchSecrets: elasticsearchSecrets,
		kibanaSecrets:        kibanaSecrets,
		curatorSecrets:       curatorSecrets,
		createWebhookSecret:  createWebhookSecret,
		pullSecrets:          pullSecrets,
		provider:             provider,
		esService:            esService,
		kbService:            kbService,
		clusterDNS:           clusterDNS,
		applyTrial:           applyTrial,
	}
}

type elasticsearchComponent struct {
	logStorage           *operatorv1.LogStorage
	installation         *operatorv1.Installation
	elasticsearch        *esv1.Elasticsearch
	kibana               *kbv1.Kibana
	clusterConfig        *ElasticsearchClusterConfig
	elasticsearchSecrets []*corev1.Secret
	kibanaSecrets        []*corev1.Secret
	curatorSecrets       []*corev1.Secret
	createWebhookSecret  bool
	pullSecrets          []*corev1.Secret
	provider             operatorv1.Provider
	esService            *corev1.Service
	kbService            *corev1.Service
	clusterDNS           string
	applyTrial           bool
}

func (es *elasticsearchComponent) Objects() ([]runtime.Object, []runtime.Object) {
	var toCreate, toDelete []runtime.Object

	if es.logStorage != nil {
		if !stringsutil.StringInSlice(LogStorageFinalizer, es.logStorage.GetFinalizers()) {
			es.logStorage.SetFinalizers(append(es.logStorage.GetFinalizers(), LogStorageFinalizer))
		}
	}

	// Doesn't matter what the cluster type is, if LogStorage exists and the DeletionTimestamp is set finalized the
	// deletion
	if es.logStorage != nil && es.logStorage.DeletionTimestamp != nil {
		finalizeCleanup := true
		if es.elasticsearch != nil {
			if es.elasticsearch.DeletionTimestamp == nil {
				toDelete = append(toDelete, es.elasticsearch)
			}
			finalizeCleanup = false
		}

		if es.kibana != nil {
			if es.kibana.DeletionTimestamp == nil {
				toDelete = append(toDelete, es.kibana)
			}
			finalizeCleanup = false
		}

		if finalizeCleanup {
			es.logStorage.SetFinalizers(stringsutil.RemoveStringInSlice(LogStorageFinalizer, es.logStorage.GetFinalizers()))
		}

		toCreate = append(toCreate, es.logStorage)
		return toCreate, toDelete
	}

	if es.installation.Spec.ClusterManagementType != operatorv1.ClusterManagementTypeManaged {
		// Write back LogStorage CR to persist any changes
		toCreate = append(toCreate, es.logStorage)

		// ECK CRs
		toCreate = append(toCreate,
			createNamespace(ECKOperatorNamespace, es.provider == operatorv1.ProviderOpenShift),
		)

		toCreate = append(toCreate, secretsToRuntimeObjects(CopySecrets(ECKOperatorNamespace, es.pullSecrets...)...)...)

		toCreate = append(toCreate,
			es.eckOperatorClusterRole(),
			es.eckOperatorClusterRoleBinding(),
			es.eckOperatorServiceAccount(),
			es.webhookService(),
			es.elasticWebhookConfiguration(),
		)
		// This is needed for the operator to be able to set privileged mode for pods.
		// https://docs.docker.com/ee/ucp/authorization/#secure-kubernetes-defaults
		if es.provider == operatorv1.ProviderDockerEE {
			toCreate = append(toCreate, es.eckOperatorClusterAdminClusterRoleBinding())
		}

		if es.createWebhookSecret {
			toCreate = append(toCreate, es.eckOperatorWebhookSecret())
		}
		toCreate = append(toCreate, es.eckOperatorStatefulSet())

		// Elasticsearch CRs
		toCreate = append(toCreate, createNamespace(ElasticsearchNamespace, es.provider == operatorv1.ProviderOpenShift))

		if len(es.pullSecrets) > 0 {
			toCreate = append(toCreate, secretsToRuntimeObjects(CopySecrets(ElasticsearchNamespace, es.pullSecrets...)...)...)
		}

		if len(es.elasticsearchSecrets) > 0 {
			toCreate = append(toCreate, secretsToRuntimeObjects(es.elasticsearchSecrets...)...)
		}

		toCreate = append(toCreate, es.clusterConfig.ConfigMap())
		toCreate = append(toCreate, es.elasticsearchCluster())

		// Kibana CRs
		toCreate = append(toCreate, createNamespace(KibanaNamespace, false))

		if len(es.pullSecrets) > 0 {
			toCreate = append(toCreate, secretsToRuntimeObjects(CopySecrets(KibanaNamespace, es.pullSecrets...)...)...)
		}

		if len(es.kibanaSecrets) > 0 {
			toCreate = append(toCreate, secretsToRuntimeObjects(es.kibanaSecrets...)...)
		}

		toCreate = append(toCreate, es.kibanaCR())

		// Curator CRs
		// If we have the curator secrets then create curator
		if len(es.curatorSecrets) > 0 {
			toCreate = append(toCreate, secretsToRuntimeObjects(CopySecrets(ElasticsearchNamespace, es.curatorSecrets...)...)...)
			toCreate = append(toCreate, es.curatorCronJob())
		}

		if es.applyTrial {
			toCreate = append(toCreate, es.elasticEnterpriseTrial())
		}

		// If we converted from a ManagedCluster to a Standalone or Management then we need to delete the elasticsearch
		// service as it differs between these cluster types
		if es.esService != nil && es.esService.Spec.Type == corev1.ServiceTypeExternalName {
			toDelete = append(toDelete, es.esService)
		}

		if es.kbService != nil && es.kbService.Spec.Type == corev1.ServiceTypeExternalName {
			toDelete = append(toDelete, es.kbService)
		}
	} else {
		toCreate = append(toCreate,
			createNamespace(ElasticsearchNamespace, es.provider == operatorv1.ProviderOpenShift),
			createNamespace(KibanaNamespace, es.provider == operatorv1.ProviderOpenShift),
			es.elasticsearchExternalService(),
			es.kibanaExternalService(),
		)
	}

	return toCreate, toDelete
}

func (es *elasticsearchComponent) Ready() bool {
	return true
}

func (es elasticsearchComponent) elasticsearchExternalService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchServiceName,
			Namespace: ElasticsearchNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: fmt.Sprintf("%s.%s.%s", GuardianServiceName, GuardianNamespace, es.clusterDNS),
		},
	}
}

func (es elasticsearchComponent) kibanaExternalService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      KibanaServiceName,
			Namespace: KibanaNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: fmt.Sprintf("%s.%s.%s", GuardianServiceName, GuardianNamespace, es.clusterDNS),
		},
	}
}

// generate the PVC required for the Elasticsearch nodes
func (es elasticsearchComponent) pvcTemplate() corev1.PersistentVolumeClaim {
	pvcTemplate := corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name: "elasticsearch-data", // ECK requires this name
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					"cpu":    resource.MustParse("2"),
					"memory": resource.MustParse("3Gi"),
				},
				Requests: corev1.ResourceList{
					"cpu":     resource.MustParse("1"),
					"memory":  resource.MustParse("2Gi"),
					"storage": resource.MustParse("10Gi"),
				},
			},
			StorageClassName: &es.logStorage.Spec.StorageClassName,
		},
	}

	// If the user has provided resource requirements, then use the user overrides instead
	if es.logStorage.Spec.Nodes != nil && es.logStorage.Spec.Nodes.ResourceRequirements != nil {
		userOverrides := *es.logStorage.Spec.Nodes.ResourceRequirements

		// If the user provided overrides does not contain a storage quantity, then we still need to
		// set a default
		if _, ok := userOverrides.Requests["storage"]; !ok {
			userOverrides.Requests["storage"] = resource.MustParse("10Gi")
		}

		pvcTemplate.Spec.Resources = userOverrides
	}

	return pvcTemplate
}

// Generate the pod template required for the ElasticSearch nodes (controls the ElasticSearch container)
func (es elasticsearchComponent) podTemplate() corev1.PodTemplateSpec {
	// Setup default configuration for ES container
	esContainer := corev1.Container{
		Name: "elasticsearch",
		// Important note: Following Elastic ECK docs, the recommended practice is to set
		// request and limit for memory to the same value:
		// https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-managing-compute-resources.html#k8s-compute-resources-elasticsearch
		//
		// Default values for memory request and limit taken from ECK docs:
		// https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-managing-compute-resources.html#k8s-default-behavior
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    resource.MustParse("1"),
				"memory": resource.MustParse("2Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":    resource.MustParse("1"),
				"memory": resource.MustParse("2Gi"),
			},
		},
		Env: []corev1.EnvVar{
			// Important note: Following Elastic ECK docs, the recommendation is to set
			// the Java heap size to half the size of RAM allocated to the Pod:
			// https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-managing-compute-resources.html#k8s-compute-resources-elasticsearch
			//
			// Default values for Java Heap min and max taken from ECK docs:
			// https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-jvm-heap-size.html#k8s-jvm-heap-size
			{Name: "ES_JAVA_OPTS", Value: "-Xms1G -Xmx1G"},
		},
	}

	// If the user has provided resource requirements, then use the user overrides instead
	if es.logStorage.Spec.Nodes != nil && es.logStorage.Spec.Nodes.ResourceRequirements != nil {
		userOverrides := *es.logStorage.Spec.Nodes.ResourceRequirements
		esContainer.Resources = corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    *userOverrides.Limits.Cpu(),
				"memory": *userOverrides.Limits.Memory(),
			},
			Requests: corev1.ResourceList{
				"cpu":    *userOverrides.Requests.Cpu(),
				"memory": *userOverrides.Requests.Memory(),
			},
		}

		// Now extract the memory request value to compute the recommended heap size for ES container
		recommendedHeapSize := memoryQuantityToJVMHeapSize(esContainer.Resources.Requests.Memory())

		esContainer.Env = []corev1.EnvVar{
			{
				Name:  "ES_JAVA_OPTS",
				Value: fmt.Sprintf("-Xms%v -Xmx%v", recommendedHeapSize, recommendedHeapSize),
			},
		}
	}

	// https://www.elastic.co/guide/en/elasticsearch/reference/current/vm-max-map-count.html
	trueBool := true
	var user int64 = 0
	initContainer := corev1.Container{
		Name: "elastic-internal-init-os-settings",
		SecurityContext: &corev1.SecurityContext{
			Privileged: &trueBool,
			RunAsUser:  &user,
		},
		Image: components.GetReference(components.ComponentElasticsearch, es.installation.Spec.Registry, es.installation.Spec.ImagePath),
		Command: []string{
			"sysctl",
			"-w",
			"vm.max_map_count=262144",
		},
	}

	podTemplate := corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			InitContainers:   []corev1.Container{initContainer},
			Containers:       []corev1.Container{esContainer},
			ImagePullSecrets: getImagePullSecretReferenceList(es.pullSecrets),
			NodeSelector:     es.logStorage.Spec.DataNodeSelector,
		},
	}

	return podTemplate
}

// Determine the recommended JVM heap size as a string (with appropriate unit suffix) based on
// the given resource.Quantity.
//
// Numeric calculations use the API of the inf.Dec type that resource.Quantity uses internally
// to perform arithmetic with rounding,
//
// Important note: Following Elastic ECK docs, the recommendation is to set the Java heap size
// to half the size of RAM allocated to the Pod:
// https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-managing-compute-resources.html#k8s-compute-resources-elasticsearch
//
// This recommendation does not consider space for machine learning however - we're using the
// default limit of 30% of node memory there, so we adjust accordingly.
//
// Finally limit the value to 26GiB to encourage zero-based compressed oops:
// https://www.elastic.co/blog/a-heap-of-trouble
func memoryQuantityToJVMHeapSize(q *resource.Quantity) string {
	// Get the Quantity's raw number with any scale factor applied (based any unit when it was parsed)
	// e.g.
	// "2Gi" is parsed as a Quantity with value 2147483648, scale factor 0, and returns 2147483648
	// "2G" is parsed as a Quantity with value 2, scale factor 9, and returns 2000000000
	// "1000" is parsed as a Quantity with value 1000, scale factor 0, and returns 1000
	rawMemQuantity := q.AsDec()

	// Use one third of that for the JVM heap.
	divisor := inf.NewDec(3, 0)
	halvedQuantity := new(inf.Dec).QuoRound(rawMemQuantity, divisor, 0, inf.RoundFloor)

	// The remaining operations below perform validation and possible modification of the
	// Quantity number in order to conform to Java standards for JVM arguments -Xms and -Xmx
	// (for min and max memory limits).
	// Source: https://docs.oracle.com/javase/8/docs/technotes/tools/windows/java.html

	// As part of JVM requirements, ensure that the memory quantity is a multiple of 1024. Round down to
	// the nearest multiple of 1024.
	divisor = inf.NewDec(1024, 0)
	factor := new(inf.Dec).QuoRound(halvedQuantity, divisor, 0, inf.RoundFloor)
	roundedToNearest := new(inf.Dec).Mul(factor, divisor)

	newRawMemQuantity := roundedToNearest.UnscaledBig().Int64()
	// Edge case: Ensure a minimum value of at least 2 Mi (megabytes); this could plausibly happens if
	// the user mistakenly uses the wrong format (e.g. using 1Mi instead of 1Gi)
	minLimit := inf.NewDec(2097152, 0)
	if roundedToNearest.Cmp(minLimit) < 0 {
		newRawMemQuantity = minLimit.UnscaledBig().Int64()
	}

	// Limit the JVM heap to 26GiB.
	maxLimit := inf.NewDec(27917287424, 0)
	if roundedToNearest.Cmp(maxLimit) > 0 {
		newRawMemQuantity = maxLimit.UnscaledBig().Int64()
	}

	// Note: Because we round to the nearest multiple of 1024 above and then use BinarySI format below,
	// we will always get a binary unit (e.g. Ki, Mi, Gi). However, depending on what the raw number is
	// the Quantity internal formatter might not use the most intuitive unit.
	//
	// E.g. For a raw number 1000000000, we explicitly round to 999999488 to get to the nearest 1024 multiple.
	// We then create a new Quantity, which will format its value to "976562Ki".
	// One might expect Quantity to use "Mi" instead of "Ki". However, doing so would result in rounding
	// (which Quantity does not do).
	//
	// Whereas a raw number 2684354560 requires no explicit rounding from us (since it's already a
	// multiple of 1024). Then the new Quantity will format it to "2560Mi".
	recommendedQuantity := resource.NewQuantity(newRawMemQuantity, resource.BinarySI)

	// Extract the string representation with correct unit suffix. In order to translate string to a
	// format that JVM understands, we need to remove the trailing "i" (e.g. "2Gi" becomes "2G")
	recommendedHeapSize := strings.TrimSuffix(recommendedQuantity.String(), "i")

	return recommendedHeapSize
}

// render the Elasticsearch CR that the ECK operator uses to create elasticsearch cluster
func (es elasticsearchComponent) elasticsearchCluster() *esv1.Elasticsearch {
	nodeConfig := es.logStorage.Spec.Nodes
	pvcTemplate := es.pvcTemplate()

	return &esv1.Elasticsearch{
		TypeMeta: metav1.TypeMeta{Kind: "Elasticsearch", APIVersion: "elasticsearch.k8s.elastic.co/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchName,
			Namespace: ElasticsearchNamespace,
			Annotations: map[string]string{
				"common.k8s.elastic.co/controller-version": components.ComponentElasticsearchOperator.Version,
			},
		},
		Spec: esv1.ElasticsearchSpec{
			Version: components.ComponentElasticsearch.Version,
			Image:   components.GetReference(components.ComponentElasticsearch, es.installation.Spec.Registry, es.installation.Spec.ImagePath),
			HTTP: cmnv1.HTTPConfig{
				TLS: cmnv1.TLSOptions{
					Certificate: cmnv1.SecretRef{
						SecretName: TigeraElasticsearchCertSecret,
					},
				},
			},
			NodeSets: []esv1.NodeSet{
				{
					Count: int32(nodeConfig.Count),
					Name: nodeSetName(pvcTemplate),
					Config: &cmnv1.Config{
						Data: map[string]interface{}{
							"node.master": "true",
							"node.data":   "true",
							"node.ingest": "true",
						},
					},
					VolumeClaimTemplates: []corev1.PersistentVolumeClaim{pvcTemplate},
					PodTemplate:          es.podTemplate(),
				},
			},
		},
	}
}

// nodeSetName returns thumbprint of PersistentVolumeClaim object as string.
// As storage requirements of NodeSets are immutable,
// renaming a NodeSet automatically creates a new StatefulSet with new PersistentVolumeClaim.
// https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-orchestration.html#k8s-orchestration-limitations
func nodeSetName(pvcTemplate corev1.PersistentVolumeClaim) string {
	pvcTemplateHash := fnv.New64a()
	templateBytes, err := json.Marshal(pvcTemplate)
	if err != nil {
		log.V(5).Info("Failed to create unique name for ElasticSearch NodeSet.", "err", err)
		return "es"
	}
	pvcTemplateHash.Write(templateBytes)
	return hex.EncodeToString(pvcTemplateHash.Sum(nil))
}

func (es elasticsearchComponent) eckOperatorWebhookSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ECKWebhookSecretName,
			Namespace: ECKOperatorNamespace,
		},
	}
}

func (es elasticsearchComponent) eckOperatorClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "elastic-operator",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "endpoints", "events", "persistentvolumeclaims", "secrets", "services", "configmaps"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "statefulsets"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"batch"},
				Resources: []string{"cronjobs"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"policy"},
				Resources: []string{"poddisruptionbudgets"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"elasticsearch.k8s.elastic.co"},
				Resources: []string{"elasticsearches", "elasticsearches/status", "elasticsearches/finalizers", "enterpriselicenses", "enterpriselicenses/status"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"kibana.k8s.elastic.co"},
				Resources: []string{"kibanas", "kibanas/status", "kibanas/finalizers"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"apm.k8s.elastic.co"},
				Resources: []string{"apmservers", "apmservers/status", "apmservers/finalizers"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"associations.k8s.elastic.co"},
				Resources: []string{"apmserverelasticsearchassociations", "apmserverelasticsearchassociations/status"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"admissionregistration.k8s.io"},
				Resources: []string{"mutatingwebhookconfigurations", "validatingwebhookconfigurations"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
		},
	}
}

func (es elasticsearchComponent) eckOperatorClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: ECKOperatorName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     ECKOperatorName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "elastic-operator",
				Namespace: ECKOperatorNamespace,
			},
		},
	}
}

func (es elasticsearchComponent) eckOperatorClusterAdminClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "elastic-operator-docker-enterprise",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cluster-admin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "elastic-operator",
				Namespace: ECKOperatorNamespace,
			},
		},
	}
}

func (es elasticsearchComponent) eckOperatorServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ECKOperatorName,
			Namespace: ECKOperatorNamespace,
		},
	}
}

func (es elasticsearchComponent) eckOperatorStatefulSet() *appsv1.StatefulSet {
	gracePeriod := int64(10)
	defaultMode := int32(420)

	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ECKOperatorName,
			Namespace: ECKOperatorNamespace,
			Labels: map[string]string{
				"control-plane": "elastic-operator",
				"k8s-app":       "elastic-operator",
			},
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"control-plane": "elastic-operator",
					"k8s-app":       "elastic-operator",
				},
			},
			ServiceName: ECKOperatorName,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"control-plane": "elastic-operator",
						"k8s-app":       "elastic-operator",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "elastic-operator",
					ImagePullSecrets:   getImagePullSecretReferenceList(es.pullSecrets),
					Containers: []corev1.Container{{
						Image: components.GetReference(components.ComponentElasticsearchOperator, es.installation.Spec.Registry, es.installation.Spec.ImagePath),
						Name:  "manager",
						// Verbosity level of logs. -2=Error, -1=Warn, 0=Info, 0 and above=Debug
						Args: []string{"manager", "--operator-roles", "all", "--log-verbosity=0"},
						Env: []corev1.EnvVar{
							{
								Name: "OPERATOR_NAMESPACE",
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "metadata.namespace",
									},
								},
							},
							{Name: "WEBHOOK_SECRET", Value: ECKWebhookSecretName},
							{Name: "WEBHOOK_PODS_LABEL", Value: "elastic-operator"},
							{Name: "OPERATOR_IMAGE", Value: components.GetReference(components.ComponentElasticsearchOperator, es.installation.Spec.Registry, es.installation.Spec.ImagePath)},
						},
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								"cpu":    resource.MustParse("1"),
								"memory": resource.MustParse("150Mi"),
							},
							Requests: corev1.ResourceList{
								"cpu":    resource.MustParse("100m"),
								"memory": resource.MustParse("50Mi"),
							},
						},
						Ports: []corev1.ContainerPort{{
							ContainerPort: 9443,
							Name:          "webhook-server",
							Protocol:      corev1.ProtocolTCP,
						}},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "cert",
							MountPath: "/tmp/k8s-webhook-server/serving-certs",
							ReadOnly:  true,
						}},
					}},
					TerminationGracePeriodSeconds: &gracePeriod,
					Volumes: []corev1.Volume{{
						Name: "cert",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								DefaultMode: &defaultMode,
								SecretName:  ECKWebhookSecretName,
							},
						},
					}},
				},
			},
		},
	}
}

func (es elasticsearchComponent) kibanaCR() *kbv1.Kibana {
	return &kbv1.Kibana{
		ObjectMeta: metav1.ObjectMeta{
			Name:      KibanaName,
			Namespace: KibanaNamespace,
			Labels: map[string]string{
				"k8s-app": KibanaName,
			},
			Annotations: map[string]string{
				"common.k8s.elastic.co/controller-version": components.ComponentElasticsearchOperator.Version,
			},
		},
		Spec: kbv1.KibanaSpec{
			Version: components.ComponentEckKibana.Version,
			Image:   components.GetReference(components.ComponentKibana, es.installation.Spec.Registry, es.installation.Spec.ImagePath),
			Config: &cmnv1.Config{
				Data: map[string]interface{}{
					"server": map[string]interface{}{
						"basePath":        fmt.Sprintf("/%s", KibanaBasePath),
						"rewriteBasePath": true,
					},
					"elasticsearch.ssl.certificateAuthorities": []string{"/usr/share/kibana/config/elasticsearch-certs/tls.crt"},
				},
			},
			Count: 1,
			HTTP: cmnv1.HTTPConfig{
				TLS: cmnv1.TLSOptions{
					Certificate: cmnv1.SecretRef{
						SecretName: TigeraKibanaCertSecret,
					},
				},
			},
			ElasticsearchRef: cmnv1.ObjectSelector{
				Name:      ElasticsearchName,
				Namespace: ElasticsearchNamespace,
			},
			PodTemplate: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: KibanaNamespace,
					Labels: map[string]string{
						"name":    KibanaName,
						"k8s-app": KibanaName,
					},
				},
				Spec: corev1.PodSpec{
					ImagePullSecrets: getImagePullSecretReferenceList(es.pullSecrets),
					Containers: []corev1.Container{{
						Name: "kibana",
						ReadinessProbe: &corev1.Probe{
							Handler: corev1.Handler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: fmt.Sprintf("/%s/login", KibanaBasePath),
									Port: intstr.IntOrString{
										IntVal: 5601,
									},
									Scheme: corev1.URISchemeHTTPS,
								},
							},
						},
					}},
				},
			},
		},
	}
}

func (es elasticsearchComponent) curatorCronJob() *batchv1beta.CronJob {
	var f = false
	var elasticCuratorLivenessProbe = &corev1.Probe{
		Handler: corev1.Handler{
			Exec: &corev1.ExecAction{
				Command: []string{
					"/usr/bin/curator",
					"--config",
					"/curator/curator_config.yaml",
					"--dry-run",
					"/curator/curator_action.yaml",
				},
			},
		},
	}

	const schedule = "@hourly"

	return &batchv1beta.CronJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsCuratorName,
			Namespace: ElasticsearchNamespace,
		},
		Spec: batchv1beta.CronJobSpec{
			Schedule: schedule,
			JobTemplate: batchv1beta.JobTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: EsCuratorName,
				},
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: ElasticsearchPodSpecDecorate(corev1.PodSpec{
							Containers: []corev1.Container{
								ElasticsearchContainerDecorate(corev1.Container{
									Name:          EsCuratorName,
									Image:         components.GetReference(components.ComponentEsCurator, es.installation.Spec.Registry, es.installation.Spec.ImagePath),
									Env:           es.curatorEnvVars(),
									LivenessProbe: elasticCuratorLivenessProbe,
									SecurityContext: &corev1.SecurityContext{
										RunAsNonRoot:             &f,
										AllowPrivilegeEscalation: &f,
									},
								}, DefaultElasticsearchClusterName, ElasticsearchCuratorUserSecret),
							},
							ImagePullSecrets: getImagePullSecretReferenceList(es.pullSecrets),
							RestartPolicy:    corev1.RestartPolicyOnFailure,
						}),
					},
				},
			},
		},
	}
}

func (es elasticsearchComponent) curatorEnvVars() []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "EE_FLOWS_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*es.logStorage.Spec.Retention.Flows)},
		{Name: "EE_AUDIT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*es.logStorage.Spec.Retention.AuditReports)},
		{Name: "EE_SNAPSHOT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*es.logStorage.Spec.Retention.Snapshots)},
		{Name: "EE_COMPLIANCE_REPORT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*es.logStorage.Spec.Retention.ComplianceReports)},
		{Name: "EE_MAX_TOTAL_STORAGE_PCT", Value: fmt.Sprint(maxTotalStoragePercent)},
		{Name: "EE_MAX_LOGS_STORAGE_PCT", Value: fmt.Sprint(maxLogsStoragePercent)},
	}
}

// This is a webhook service that helps with CR validations.
func (es elasticsearchComponent) webhookService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ECKWebhookName,
			Namespace: ECKOperatorNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       ECKWebhookName,
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(9443),
				},
			},
			Selector: map[string]string{"control-plane": ECKOperatorName, "k8s-app": ECKOperatorName},
		},
	}
}

// Applying this in the eck namespace will start a trial license for enterprise features.
func (es elasticsearchComponent) elasticEnterpriseTrial() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ECKEnterpriseTrial,
			Namespace: ECKOperatorNamespace,
			Labels: map[string]string{
				"license.k8s.elastic.co/type": "enterprise-trial",
			},
			Annotations: map[string]string{
				"elastic.co/eula": "accepted",
			},
		},
	}
}

// A ValidatingWebhookConfiguration is used in order to validate changes made to the Kibana and ES CR's
func (es elasticsearchComponent) elasticWebhookConfiguration() *admissionv1beta1.ValidatingWebhookConfiguration {
	path := "/validate-elasticsearch-k8s-elastic-co-v1-elasticsearch"
	failure := admissionv1beta1.Ignore
	return &admissionv1beta1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: ECKWebhookConfiguration,
		},
		Webhooks: []admissionv1beta1.Webhook{
			{
				ClientConfig: admissionv1beta1.WebhookClientConfig{
					CABundle: []byte("Cg=="), // base64 empty string
					Service: &admissionv1beta1.ServiceReference{
						Name:      ECKWebhookName,
						Namespace: ECKOperatorNamespace,
						Path:      &path,
					},
				},
				FailurePolicy: &failure,
				Name:          "elastic-es-validation-v1.k8s.elastic.co",
				Rules: []admissionv1beta1.RuleWithOperations{
					{
						Operations: []admissionv1beta1.OperationType{
							"CREATE",
							"UPDATE",
						},
						Rule: admissionv1beta1.Rule{
							APIVersions: []string{
								"v1",
							},
							Resources: []string{
								"elasticsearches",
							},
							APIGroups: []string{
								"elasticsearch.k8s.elastic.co",
							},
						},
					},
				},
			},
		},
	}
}
