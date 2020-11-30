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

	cmnv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	"github.com/elastic/cloud-on-k8s/pkg/utils/stringsutil"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"

	"gopkg.in/inf.v0"

	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
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
	ECKWebhookPortName      = "https"
	ECKEnterpriseTrial      = "eck-trial-license"
	ECKWebhookConfiguration = "elastic-webhook.k8s.elastic.co"

	ElasticsearchNamespace                = "tigera-elasticsearch"
	ElasticsearchHTTPURL                  = "tigera-secure-es-http.tigera-elasticsearch.svc"
	ElasticsearchHTTPSEndpoint            = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
	ElasticsearchName                     = "tigera-secure"
	ElasticsearchConfigMapName            = "tigera-secure-elasticsearch"
	ElasticsearchServiceName              = "tigera-secure-es-http"
	ElasticsearchSecureSettingsSecretName = "tigera-elasticsearch-secure-settings"

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

	EsCuratorName           = "elastic-curator"
	EsCuratorServiceAccount = "tigera-elastic-curator"

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

const (
	keystoreInitVolumeName = "elastic-internal-secure-settings"
	keystoreInitMountPath  = "/mnt/elastic-internal/secure-settings"

	keystoreInitScript = `#!/usr/bin/env bash
set -eux

echo "Initializing keystore."

# create a keystore in the default data path
# We use they elasticsearch-keystore list to test if the keystore has been initialized.
! /usr/share/elasticsearch/bin/elasticsearch-keystore list && /usr/share/elasticsearch/bin/elasticsearch-keystore create

# add all existing secret entries into it
for filename in  /mnt/elastic-internal/secure-settings/*; do
	[[ -e "$filename" ]] || continue # glob does not match
	key=$(basename "$filename")
	echo "Adding $key to the keystore."
	/usr/share/elasticsearch/bin/elasticsearch-keystore add-file "$key" "$filename" -f
done

echo "Keystore initialization successful."
`
)

// Elasticsearch renders the
func LogStorage(
	logStorage *operatorv1.LogStorage,
	installation *operatorv1.InstallationSpec,
	managementCluster *operatorv1.ManagementCluster,
	managementClusterConnection *operatorv1.ManagementClusterConnection,
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
	applyTrial bool,
	dexCfg DexRelyingPartyConfig) Component {

	return &elasticsearchComponent{
		logStorage:                  logStorage,
		installation:                installation,
		managementCluster:           managementCluster,
		managementClusterConnection: managementClusterConnection,
		elasticsearch:               elasticsearch,
		kibana:                      kibana,
		clusterConfig:               clusterConfig,
		elasticsearchSecrets:        elasticsearchSecrets,
		kibanaSecrets:               kibanaSecrets,
		curatorSecrets:              curatorSecrets,
		createWebhookSecret:         createWebhookSecret,
		pullSecrets:                 pullSecrets,
		provider:                    provider,
		esService:                   esService,
		kbService:                   kbService,
		clusterDNS:                  clusterDNS,
		applyTrial:                  applyTrial,
		dexCfg:                      dexCfg,
	}
}

type elasticsearchComponent struct {
	logStorage                  *operatorv1.LogStorage
	installation                *operatorv1.InstallationSpec
	managementCluster           *operatorv1.ManagementCluster
	managementClusterConnection *operatorv1.ManagementClusterConnection
	elasticsearch               *esv1.Elasticsearch
	kibana                      *kbv1.Kibana
	clusterConfig               *ElasticsearchClusterConfig
	elasticsearchSecrets        []*corev1.Secret
	kibanaSecrets               []*corev1.Secret
	curatorSecrets              []*corev1.Secret
	createWebhookSecret         bool
	pullSecrets                 []*corev1.Secret
	provider                    operatorv1.Provider
	esService                   *corev1.Service
	kbService                   *corev1.Service
	clusterDNS                  string
	applyTrial                  bool
	dexCfg                      DexRelyingPartyConfig
}

func (es *elasticsearchComponent) SupportedOSType() OSType {
	return OSTypeLinux
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

	if es.managementClusterConnection == nil {
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

		// Apply the pod security policies for all providers except OpenShift
		if es.provider != operatorv1.ProviderOpenShift {
			toCreate = append(toCreate,
				es.eckOperatorPodSecurityPolicy(),
				es.elasticsearchClusterRoleBinding(),
				es.elasticsearchClusterRole(),
				es.elasticsearchPodSecurityPolicy(),
				es.kibanaClusterRoleBinding(),
				es.kibanaClusterRole(),
				es.kibanaPodSecurityPolicy())
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

		toCreate = append(toCreate, es.elasticsearchServiceAccount())
		toCreate = append(toCreate, es.clusterConfig.ConfigMap())

		secureSettings := es.secureSettingsSecret()
		if len(secureSettings.Data) > 0 {
			toCreate = append(toCreate, secureSettings)
		}

		toCreate = append(toCreate, es.elasticsearchCluster(len(secureSettings.Data) > 0))

		// Kibana CRs
		toCreate = append(toCreate, createNamespace(KibanaNamespace, false))
		toCreate = append(toCreate, es.kibanaServiceAccount())

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
			toCreate = append(toCreate, es.esCuratorServiceAccount())

			// If the provider is not OpenShift apply the pod security policy for the curator.
			if es.provider != operatorv1.ProviderOpenShift {
				toCreate = append(toCreate,
					es.curatorClusterRole(),
					es.curatorClusterRoleBinding(),
					es.curatorPodSecurityPolicy())
			}

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

	if es.dexCfg != nil {
		toCreate = append(toCreate, secretsToRuntimeObjects(es.dexCfg.RequiredSecrets(ElasticsearchNamespace)...)...)
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

func (es elasticsearchComponent) elasticsearchServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-elasticsearch",
			Namespace: ElasticsearchNamespace,
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
				Requests: corev1.ResourceList{
					"storage": resource.MustParse("10Gi"),
				},
			},
			StorageClassName: &es.logStorage.Spec.StorageClassName,
		},
	}

	// If the user has provided resource requirements, then use the user overrides instead
	if es.logStorage.Spec.Nodes != nil && es.logStorage.Spec.Nodes.ResourceRequirements != nil {
		userOverrides := *es.logStorage.Spec.Nodes.ResourceRequirements
		pvcTemplate.Spec.Resources = overridePvcRequirements(pvcTemplate.Spec.Resources, userOverrides)
	}

	return pvcTemplate
}

// Generate the pod template required for the ElasticSearch nodes (controls the ElasticSearch container)
func (es elasticsearchComponent) podTemplate() corev1.PodTemplateSpec {
	// Setup default configuration for ES container. For more information on managing resources, see:
	// https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-managing-compute-resources.html and
	// https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-jvm-heap-size.html#k8s-jvm-heap-size

	var volumeMounts []corev1.VolumeMount
	if es.dexCfg != nil {
		volumeMounts = append(volumeMounts, es.dexCfg.RequiredVolumeMounts()...)
	}

	esContainer := corev1.Container{
		Name: "elasticsearch",
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"cpu":    resource.MustParse("1"),
				"memory": resource.MustParse("4Gi"),
			},
			Requests: corev1.ResourceList{
				"cpu":    resource.MustParse("250m"),
				"memory": resource.MustParse("4Gi"),
			},
		},
		Env: []corev1.EnvVar{
			// Set to 30% of the default memory, such that resources can be divided over ES, Lucene and ML.
			{Name: "ES_JAVA_OPTS", Value: "-Xms1398101K -Xmx1398101K"},
		},
		VolumeMounts: volumeMounts,
	}

	// If the user has provided resource requirements, then use the user overrides instead
	if es.logStorage.Spec.Nodes != nil && es.logStorage.Spec.Nodes.ResourceRequirements != nil {
		userOverrides := *es.logStorage.Spec.Nodes.ResourceRequirements
		esContainer.Resources = overrideResourceRequirements(esContainer.Resources, userOverrides)

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
	initOSSettingsContainer := corev1.Container{
		Name: "elastic-internal-init-os-settings",
		SecurityContext: &corev1.SecurityContext{
			Privileged: Bool(true),
			RunAsUser:  Int64(0),
		},
		Image: components.GetReference(components.ComponentElasticsearch, es.installation.Registry, es.installation.ImagePath),
		Command: []string{
			"/bin/sh",
		},
		Args: []string{
			"-c",
			"echo 262144 > /proc/sys/vm/max_map_count",
		},
	}

	initContainers := []corev1.Container{initOSSettingsContainer}
	annotations := map[string]string{}
	if es.dexCfg != nil {
		initKeystore := corev1.Container{
			Name:  "elastic-internal-init-keystore",
			Image: components.GetReference(components.ComponentElasticsearch, es.installation.Registry, es.installation.ImagePath),
			SecurityContext: &corev1.SecurityContext{
				Privileged: Bool(false),
			},
			Command: []string{"/usr/bin/env", "bash", "-c", keystoreInitScript},
			VolumeMounts: []corev1.VolumeMount{{
				Name:      keystoreInitVolumeName,
				MountPath: keystoreInitMountPath,
				ReadOnly:  true,
			}},
		}
		initContainers = append(initContainers, initKeystore)
		annotations = es.dexCfg.RequiredAnnotations()
	}

	var volumes []corev1.Volume

	if es.dexCfg != nil {
		volumes = es.dexCfg.RequiredVolumes()
	}
	podTemplate := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			InitContainers:     initContainers,
			Containers:         []corev1.Container{esContainer},
			ImagePullSecrets:   getImagePullSecretReferenceList(es.pullSecrets),
			NodeSelector:       es.logStorage.Spec.DataNodeSelector,
			ServiceAccountName: "tigera-elasticsearch",
			Volumes:            volumes,
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
func (es elasticsearchComponent) elasticsearchCluster(secureSettings bool) *esv1.Elasticsearch {
	elasticsearch := &esv1.Elasticsearch{
		TypeMeta: metav1.TypeMeta{Kind: "Elasticsearch", APIVersion: "elasticsearch.k8s.elastic.co/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchName,
			Namespace: ElasticsearchNamespace,
			Annotations: map[string]string{
				"common.k8s.elastic.co/controller-version": components.ComponentElasticsearchOperator.Version,
			},
		},
		Spec: esv1.ElasticsearchSpec{
			Version: components.ComponentEckElasticsearch.Version,
			Image:   components.GetReference(components.ComponentElasticsearch, es.installation.Registry, es.installation.ImagePath),
			HTTP: cmnv1.HTTPConfig{
				TLS: cmnv1.TLSOptions{
					Certificate: cmnv1.SecretRef{
						SecretName: TigeraElasticsearchCertSecret,
					},
				},
			},
			NodeSets: es.nodeSets(),
		},
	}

	if secureSettings {
		elasticsearch.Spec.SecureSettings = []cmnv1.SecretSource{{
			SecretName: ElasticsearchSecureSettingsSecretName,
		}}
	}

	return elasticsearch
}

func (es elasticsearchComponent) secureSettingsSecret() *corev1.Secret {
	secureSettings := make(map[string][]byte)

	if es.dexCfg != nil {
		secureSettings["xpack.security.authc.realms.oidc.oidc1.rp.client_secret"] = es.dexCfg.ClientSecret()
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchSecureSettingsSecretName,
			Namespace: ElasticsearchNamespace,
		},
		Data: secureSettings,
	}
}

// nodeSets calculates the number of NodeSets needed for the Elasticsearch cluster. Multiple NodeSets are returned only
// if the "nodeSets" field has been set in the LogStorage CR. The number of Nodes for the cluster will be distributed as
// evenly as possible between the NodeSets.
func (es elasticsearchComponent) nodeSets() []esv1.NodeSet {
	nodeConfig := es.logStorage.Spec.Nodes
	pvcTemplate := es.pvcTemplate()

	var nodeSets []esv1.NodeSet
	if nodeConfig.NodeSets == nil || len(nodeConfig.NodeSets) < 1 {
		nodeSet := es.nodeSetTemplate(pvcTemplate)
		nodeSet.Name = nodeSetName(pvcTemplate)
		nodeSet.Count = int32(nodeConfig.Count)
		nodeSet.PodTemplate = es.podTemplate()

		nodeSets = append(nodeSets, nodeSet)
	} else {
		baseNumNodes := nodeConfig.Count / int64(len(nodeConfig.NodeSets))

		for i, nodeSetConfig := range nodeConfig.NodeSets {
			numNodes := baseNumNodes
			// Increase the first nodeConfig.Count % nodeConfig.NodeSets by 1, so that the sum of nodes in each
			// NodeSet is equal to nodeConfig.Count.
			if int64(i) < nodeConfig.Count%int64(len(nodeConfig.NodeSets)) {
				numNodes++
			}

			// Don't create a NodeSet with 0 Nodes.
			if numNodes < 1 {
				// If count is less than 1 this iteration it will be less than one all subsequent iterations.
				break
			}

			nodeSet := es.nodeSetTemplate(pvcTemplate)
			// Each NodeSet needs a unique name, so just add the index as a suffix
			nodeSet.Name = fmt.Sprintf("%s-%d", nodeSetName(pvcTemplate), i)
			nodeSet.Count = int32(numNodes)

			podTemplate := es.podTemplate()

			// If SelectionAttributes is set that means that the user wants the Elasticsearch Nodes and Replicas
			// spread out across K8s nodes with specific attributes, like availability zone. Therefore, the Node Affinity
			// is set for the NodeSet's pod template and each running instance of elasticsearch is made aware of the
			// attributes of the K8s node it is running on, via "node.attr" and "cluster.routing.allocation.awareness.attributes".
			// Making each Elasticsearch instance aware of the K8s node it's running on allows the Elasticsearch cluster
			// to assign shard replicas to nodes with different attributes than the node of the primary shard.
			if nodeSetConfig.SelectionAttributes != nil {
				var esAwarenessAttrs []string
				var nodeSelectorRequirements []corev1.NodeSelectorRequirement

				for _, attr := range nodeSetConfig.SelectionAttributes {
					nodeSet.Config.Data[fmt.Sprintf("node.attr.%s", attr.Name)] = attr.Value
					esAwarenessAttrs = append(esAwarenessAttrs, attr.Name)

					nodeSelectorRequirements = append(
						nodeSelectorRequirements,
						corev1.NodeSelectorRequirement{
							Key:      attr.NodeLabel,
							Operator: corev1.NodeSelectorOpIn,
							Values:   []string{attr.Value},
						},
					)
				}

				nodeSet.Config.Data["cluster.routing.allocation.awareness.attributes"] = strings.Join(esAwarenessAttrs, ",")

				podTemplate.Spec.Affinity = &corev1.Affinity{
					NodeAffinity: &corev1.NodeAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
							NodeSelectorTerms: []corev1.NodeSelectorTerm{{
								MatchExpressions: nodeSelectorRequirements,
							}},
						},
					},
				}
			}

			nodeSet.PodTemplate = podTemplate

			nodeSets = append(nodeSets, nodeSet)
		}
	}

	return nodeSets
}

// nodeSetTemplate returns a NodeSet with default values needed for all Elasticsearch cluster setups.
//
// Note that this does not return a complete NodeSet, fields like Name and Count will at least need to be set on the returned
// NodeSet
func (es elasticsearchComponent) nodeSetTemplate(pvcTemplate corev1.PersistentVolumeClaim) esv1.NodeSet {
	config := map[string]interface{}{
		"node.master":                 "true",
		"node.data":                   "true",
		"node.ingest":                 "true",
		"cluster.max_shards_per_node": 10000,
	}
	if es.dexCfg != nil {
		config["xpack.security.authc.realms.oidc.oidc1"] = map[string]interface{}{
			"order":                       1,
			"rp.client_id":                DexClientId,
			"op.jwkset_path":              es.dexCfg.JWKSURI(),
			"op.userinfo_endpoint":        es.dexCfg.UserInfoURI(),
			"op.token_endpoint":           es.dexCfg.TokenURI(),
			"claims.principal":            es.dexCfg.UsernameClaim(),
			"claims.groups":               es.dexCfg.GroupsClaim(),
			"rp.response_type":            "code",
			"rp.requested_scopes":         es.dexCfg.RequestedScopes(),
			"rp.redirect_uri":             fmt.Sprintf("%s/tigera-kibana/api/security/oidc/callback", es.dexCfg.ManagerURI()),
			"rp.post_logout_redirect_uri": fmt.Sprintf("%s/tigera-kibana/logged_out", es.dexCfg.ManagerURI()),
			"op.issuer":                   fmt.Sprintf("%s/dex", es.dexCfg.ManagerURI()),
			"op.authorization_endpoint":   fmt.Sprintf("%s/dex/auth", es.dexCfg.ManagerURI()),
			"ssl.certificate_authorities": []string{"/usr/share/elasticsearch/config/dex/tls-dex.crt"},
		}
	}

	return esv1.NodeSet{
		// This is configuration that ends up in /usr/share/elasticsearch/config/elasticsearch.yml on the Elastic container.
		Config: &cmnv1.Config{
			Data: config,
		},
		VolumeClaimTemplates: []corev1.PersistentVolumeClaim{pvcTemplate},
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

	if _, err := pvcTemplateHash.Write(templateBytes); err != nil {
		log.V(5).Info("Failed to create unique name for ElasticSearch NodeSet.", "err", err)
		return "es"
	}

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
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{"authorization.k8s.io"},
			Resources: []string{"subjectaccessreviews"},
			Verbs:     []string{"create"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods", "endpoints", "events", "persistentvolumeclaims", "secrets", "services", "configmaps", "serviceaccounts"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments", "statefulsets", "daemonsets"},
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
			APIGroups: []string{"enterprisesearch.k8s.elastic.co"},
			Resources: []string{"enterprisesearches", "enterprisesearches/status", "enterprisesearches/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"beat.k8s.elastic.co"},
			Resources: []string{"beats", "beats/status", "beats/finalizers"},
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
	}

	if es.provider != operatorv1.ProviderOpenShift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{ECKOperatorName},
		})
	}

	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "elastic-operator",
		},
		Rules: rules,
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

// creating this service account without any role bindings to stop curator getting associated with default SA
// This allows us to create stricter PodSecurityPolicy for the curator as PSP are based on service account.
func (es elasticsearchComponent) esCuratorServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsCuratorServiceAccount,
			Namespace: ElasticsearchNamespace,
		},
	}
}

func (es elasticsearchComponent) eckOperatorStatefulSet() *appsv1.StatefulSet {
	gracePeriod := int64(10)
	defaultMode := int32(420)

	hostNetwork := false
	dnsPolicy := corev1.DNSClusterFirst
	if es.installation.KubernetesProvider == operatorv1.ProviderEKS &&
		es.installation.CNI.Type == operatorv1.PluginCalico {
		// Workaround the fact that webhooks don't work for non-host-networked pods
		// when in this networking mode on EKS, because the control plane nodes don't run
		// Calico.
		hostNetwork = true

		// Adjust DNS policy so we can access in-cluster services.
		dnsPolicy = corev1.DNSClusterFirstWithHostNet
	}

	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{Kind: "StatefulSet", APIVersion: "apps/v1"},
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
					Annotations: map[string]string{
						// Rename the fields "error" to "error.message" and "source" to "event.source"
						// This is to avoid a conflict with the ECS "error" and "source" documents.
						"co.elastic.logs/raw": "[{\"type\":\"container\",\"json.keys_under_root\":true,\"paths\":[\"/var/log/containers/*${data.kubernetes.container.id}.log\"],\"processors\":[{\"convert\":{\"mode\":\"rename\",\"ignore_missing\":true,\"fields\":[{\"from\":\"error\",\"to\":\"_error\"}]}},{\"convert\":{\"mode\":\"rename\",\"ignore_missing\":true,\"fields\":[{\"from\":\"_error\",\"to\":\"error.message\"}]}},{\"convert\":{\"mode\":\"rename\",\"ignore_missing\":true,\"fields\":[{\"from\":\"source\",\"to\":\"_source\"}]}},{\"convert\":{\"mode\":\"rename\",\"ignore_missing\":true,\"fields\":[{\"from\":\"_source\",\"to\":\"event.source\"}]}}]}]",
					},
				},
				Spec: corev1.PodSpec{
					DNSPolicy:          dnsPolicy,
					ServiceAccountName: "elastic-operator",
					ImagePullSecrets:   getImagePullSecretReferenceList(es.pullSecrets),
					HostNetwork:        hostNetwork,
					Containers: []corev1.Container{{
						Image: components.GetReference(components.ComponentElasticsearchOperator, es.installation.Registry, es.installation.ImagePath),
						Name:  "manager",
						// Verbosity level of logs. -2=Error, -1=Warn, 0=Info, 0 and above=Debug
						Args: []string{
							"manager",
							"--log-verbosity=0",
							"--metrics-port=0",
							"--container-registry=" + es.installation.Registry,
							"--max-concurrent-reconciles=3",
							"--ca-cert-validity=8760h",
							"--ca-cert-rotate-before=24h",
							"--cert-validity=8760h",
							"--cert-rotate-before=24h",
							"--enable-webhook",
						},
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
							{Name: "OPERATOR_IMAGE", Value: components.GetReference(components.ComponentElasticsearchOperator, es.installation.Registry, es.installation.ImagePath)},
						},
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								"cpu":    resource.MustParse("1"),
								"memory": resource.MustParse("512Mi"),
							},
							Requests: corev1.ResourceList{
								"cpu":    resource.MustParse("100m"),
								"memory": resource.MustParse("512Mi"),
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

func (es elasticsearchComponent) eckOperatorPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := basePodSecurityPolicy()
	psp.GetObjectMeta().SetName(ECKOperatorName)
	return psp
}

func (es elasticsearchComponent) kibanaServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tigera-kibana",
			Namespace: KibanaNamespace,
		},
	}
}

func (es elasticsearchComponent) kibanaCR() *kbv1.Kibana {
	config := map[string]interface{}{
		"server": map[string]interface{}{
			"basePath":        fmt.Sprintf("/%s", KibanaBasePath),
			"rewriteBasePath": true,
		},
		"elasticsearch.ssl.certificateAuthorities": []string{"/usr/share/kibana/config/elasticsearch-certs/tls.crt"},
	}

	if es.dexCfg != nil {
		config["xpack.security.authc.providers"] = []string{"oidc", "basic"}
		config["xpack.security.authc.oidc.realm"] = "oidc1"
		config["server.xsrf.whitelist"] = []string{"/api/security/oidc/initiate_login"}
	}

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
			Image:   components.GetReference(components.ComponentKibana, es.installation.Registry, es.installation.ImagePath),
			Config: &cmnv1.Config{
				Data: config,
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
					ImagePullSecrets:   getImagePullSecretReferenceList(es.pullSecrets),
					ServiceAccountName: "tigera-kibana",
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
	var t = true
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
					Labels: map[string]string{
						"k8s-app": EsCuratorName,
					},
				},
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"k8s-app": EsCuratorName,
							},
						},
						Spec: ElasticsearchPodSpecDecorate(corev1.PodSpec{
							Containers: []corev1.Container{
								ElasticsearchContainerDecorate(corev1.Container{
									Name:          EsCuratorName,
									Image:         components.GetReference(components.ComponentEsCurator, es.installation.Registry, es.installation.ImagePath),
									Env:           es.curatorEnvVars(),
									LivenessProbe: elasticCuratorLivenessProbe,
									SecurityContext: &corev1.SecurityContext{
										RunAsNonRoot:             &t,
										AllowPrivilegeEscalation: &f,
									},
								}, DefaultElasticsearchClusterName, ElasticsearchCuratorUserSecret),
							},
							ImagePullSecrets:   getImagePullSecretReferenceList(es.pullSecrets),
							RestartPolicy:      corev1.RestartPolicyOnFailure,
							ServiceAccountName: EsCuratorServiceAccount,
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

func (es elasticsearchComponent) curatorClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: EsCuratorName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Allow access to the pod security policy in case this is enforced on the cluster
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{EsCuratorName},
			},
		},
	}
}

func (es elasticsearchComponent) curatorClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: EsCuratorName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     EsCuratorName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      EsCuratorServiceAccount,
				Namespace: ElasticsearchNamespace,
			},
		},
	}
}

func (es elasticsearchComponent) curatorPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := basePodSecurityPolicy()
	psp.GetObjectMeta().SetName(EsCuratorName)
	return psp
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
					Name:       ECKWebhookPortName,
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
	pathES := "/validate-elasticsearch-k8s-elastic-co-v1-elasticsearch"
	pathKibana := "/validate-kibana-k8s-elastic-co-v1-kibana"
	pathAPMServer := "/validate-apm-k8s-elastic-co-v1-apmserver"
	pathBeat := "/validate-beat-k8s-elastic-co-v1beta1-beat"
	failure := admissionv1beta1.Ignore
	return &admissionv1beta1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: ECKWebhookConfiguration,
		},
		// Note that we have only included the latest version of each webhook from the ECK manifests.
		Webhooks: []admissionv1beta1.ValidatingWebhook{
			{
				ClientConfig: admissionv1beta1.WebhookClientConfig{
					CABundle: []byte("Cg=="), // base64 empty string
					Service: &admissionv1beta1.ServiceReference{
						Name:      ECKWebhookName,
						Namespace: ECKOperatorNamespace,
						Path:      &pathAPMServer,
					},
				},
				FailurePolicy: &failure,
				Name:          "elastic-apm-validation-v1.k8s.elastic.co",
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
								"apmservers",
							},
							APIGroups: []string{
								"apm.k8s.elastic.co",
							},
						},
					},
				},
			},
			{
				ClientConfig: admissionv1beta1.WebhookClientConfig{
					CABundle: []byte("Cg=="), // base64 empty string
					Service: &admissionv1beta1.ServiceReference{
						Name:      ECKWebhookName,
						Namespace: ECKOperatorNamespace,
						Path:      &pathBeat,
					},
				},
				FailurePolicy: &failure,
				Name:          "elastic-beat-validation-v1beta1.k8s.elastic.co",
				Rules: []admissionv1beta1.RuleWithOperations{
					{
						Operations: []admissionv1beta1.OperationType{
							"CREATE",
							"UPDATE",
						},
						Rule: admissionv1beta1.Rule{
							APIVersions: []string{
								"v1beta1",
							},
							Resources: []string{
								"beats",
							},
							APIGroups: []string{
								"beat.k8s.elastic.co",
							},
						},
					},
				},
			},
			{
				ClientConfig: admissionv1beta1.WebhookClientConfig{
					CABundle: []byte("Cg=="), // base64 empty string
					Service: &admissionv1beta1.ServiceReference{
						Name:      ECKWebhookName,
						Namespace: ECKOperatorNamespace,
						Path:      &pathKibana,
					},
				},
				FailurePolicy: &failure,
				Name:          "elastic-kb-validation-v1.k8s.elastic.co",
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
								"kibanas",
							},
							APIGroups: []string{
								"kibana.k8s.elastic.co",
							},
						},
					},
				},
			},
			{
				ClientConfig: admissionv1beta1.WebhookClientConfig{
					CABundle: []byte("Cg=="), // base64 empty string
					Service: &admissionv1beta1.ServiceReference{
						Name:      ECKWebhookName,
						Namespace: ECKOperatorNamespace,
						Path:      &pathES,
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

func (es elasticsearchComponent) elasticsearchClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-elasticsearch",
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Allow access to the pod security policy in case this is enforced on the cluster
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"tigera-elasticsearch"},
			},
		},
	}
}

func (es elasticsearchComponent) elasticsearchClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-elasticsearch",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-elasticsearch",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-elasticsearch",
				Namespace: ElasticsearchNamespace,
			},
		},
	}
}

func (es elasticsearchComponent) elasticsearchPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	trueBool := true
	ptrBoolTrue := &trueBool
	psp := basePodSecurityPolicy()
	psp.GetObjectMeta().SetName("tigera-elasticsearch")
	psp.Spec.Privileged = true
	psp.Spec.AllowPrivilegeEscalation = ptrBoolTrue
	psp.Spec.RequiredDropCapabilities = nil
	psp.Spec.AllowedCapabilities = []corev1.Capability{
		corev1.Capability("CAP_CHOWN"),
	}
	psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyRunAsAny
	return psp
}

func (es elasticsearchComponent) kibanaClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-kibana",
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Allow access to the pod security policy in case this is enforced on the cluster
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{"tigera-kibana"},
			},
		},
	}
}

func (es elasticsearchComponent) kibanaClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-kibana",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "tigera-kibana",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "tigera-kibana",
				Namespace: KibanaNamespace,
			},
		},
	}
}

func (es elasticsearchComponent) kibanaPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := basePodSecurityPolicy()
	psp.GetObjectMeta().SetName("tigera-kibana")
	return psp
}

// overrideResourceRequirements replaces individual ResourceRequirements field's default value with user's value.
// - If user provided both Limits and Requests, use them.
// - If user provided just Limits, and Limits is <= default Requests, set Requests value as user's Limits value,
// - If user provided just Requests, and Requests is >= default Limits, set Limits value as user's Requests value.
func overrideResourceRequirements(defaultReq corev1.ResourceRequirements, userOverrides corev1.ResourceRequirements) corev1.ResourceRequirements {
	updatedReq := defaultReq
	if _, ok := userOverrides.Limits["cpu"]; ok {
		updatedReq.Limits["cpu"] = *userOverrides.Limits.Cpu()
		if _, ok := userOverrides.Requests["cpu"]; !ok && defaultReq.Requests.Cpu().Value() > userOverrides.Limits.Cpu().Value() {
			updatedReq.Requests["cpu"] = *userOverrides.Limits.Cpu()
		}
	}
	if _, ok := userOverrides.Limits["memory"]; ok {
		updatedReq.Limits["memory"] = *userOverrides.Limits.Memory()
		if _, ok := userOverrides.Requests["memory"]; !ok && defaultReq.Requests.Memory().Value() > userOverrides.Limits.Memory().Value() {
			updatedReq.Requests["memory"] = *userOverrides.Limits.Memory()
		}
	}
	if _, ok := userOverrides.Requests["cpu"]; ok {
		updatedReq.Requests["cpu"] = *userOverrides.Requests.Cpu()
		if _, ok := userOverrides.Limits["cpu"]; !ok && defaultReq.Limits.Cpu().Value() < userOverrides.Requests.Cpu().Value() {
			updatedReq.Limits["cpu"] = *userOverrides.Requests.Cpu()
		}
	}
	if _, ok := userOverrides.Requests["memory"]; ok {
		updatedReq.Requests["memory"] = *userOverrides.Requests.Memory()
		if _, ok := userOverrides.Limits["memory"]; !ok && defaultReq.Limits.Memory().Value() < userOverrides.Requests.Memory().Value() {
			updatedReq.Limits["memory"] = *userOverrides.Requests.Memory()
		}
	}
	return updatedReq
}

// overridePvcRequirements replaces default storage requirement value with user's value.
// - If user provided both Limits and Requests, use them
// - If user has provided just Limits, and Limits is <= default Requests, set Requests value as user's Limits value.
// We don not set default Limits for storage, so don't have to handle case where user has set only Requests.
func overridePvcRequirements(defaultReq corev1.ResourceRequirements, userOverrides corev1.ResourceRequirements) corev1.ResourceRequirements {
	updatedReq := defaultReq
	if _, ok := userOverrides.Limits["storage"]; ok {
		updatedReq.Limits = corev1.ResourceList{
			"storage": userOverrides.Limits["storage"],
		}

		if _, ok := userOverrides.Requests["storage"]; !ok {
			defaultStorage := defaultReq.Requests["storage"]
			requestedStorage := userOverrides.Limits["storage"]
			if defaultStorage.Value() > requestedStorage.Value() {
				updatedReq.Requests["storage"] = userOverrides.Limits["storage"]
			}
		}
	}

	if _, ok := userOverrides.Requests["storage"]; ok {
		updatedReq.Requests["storage"] = userOverrides.Requests["storage"]
	}
	return updatedReq
}
