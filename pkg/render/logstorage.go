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
	"net/url"
	"strings"

	"github.com/tigera/operator/pkg/common"

	cmnv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/ptr"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
)

type ElasticsearchLicenseType string

const (
	ECKOperatorName         = "elastic-operator"
	ECKOperatorNamespace    = "tigera-eck-operator"
	ECKLicenseConfigMapName = "elastic-licensing"

	ElasticsearchNamespace = "tigera-elasticsearch"

	TigeraElasticsearchCertSecret         = "tigera-secure-elasticsearch-cert"
	TigeraElasticsearchInternalCertSecret = "tigera-secure-internal-elasticsearch-cert"

	ElasticsearchName                     = "tigera-secure"
	ElasticsearchServiceName              = "tigera-secure-es-http"
	ESGatewayServiceName                  = "tigera-secure-es-gateway-http"
	ElasticsearchSecureSettingsSecretName = "tigera-elasticsearch-secure-settings"
	ElasticsearchOperatorUserSecret       = "tigera-ee-operator-elasticsearch-access"
	ElasticsearchAdminUserSecret          = "tigera-secure-es-elastic-user"

	KibanaName               = "tigera-secure"
	KibanaNamespace          = "tigera-kibana"
	KibanaPublicCertSecret   = "tigera-secure-es-gateway-http-certs-public"
	KibanaInternalCertSecret = "tigera-secure-kb-http-certs-public"
	TigeraKibanaCertSecret   = "tigera-secure-kibana-cert"
	KibanaDefaultCertPath    = "/etc/ssl/kibana/ca.pem"
	KibanaBasePath           = "tigera-kibana"
	KibanaServiceName        = "tigera-secure-kb-http"
	KibanaDefaultRoute       = "/app/kibana#/dashboards?%s&title=%s"

	DefaultElasticsearchClusterName = "cluster"
	DefaultElasticsearchReplicas    = 0
	DefaultElasticStorageGi         = 10

	EsCuratorName           = "elastic-curator"
	EsCuratorServiceAccount = "tigera-elastic-curator"

	OIDCUsersConfigMapName = "tigera-known-oidc-users"
	OIDCUsersEsSecreteName = "tigera-oidc-users-elasticsearch-credentials"

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

	ElasticsearchLicenseTypeBasic           ElasticsearchLicenseType = "basic"
	ElasticsearchLicenseTypeEnterprise      ElasticsearchLicenseType = "enterprise"
	ElasticsearchLicenseTypeEnterpriseTrial ElasticsearchLicenseType = "enterprise_trial"
	ElasticsearchLicenseTypeUnknown         ElasticsearchLicenseType = ""

	EsManagerRole        = "es-manager"
	EsManagerRoleBinding = "es-manager"

	KibanaTLSAnnotationHash        = "hash.operator.tigera.io/kb-secrets"
	ElasticsearchTLSHashAnnotation = "hash.operator.tigera.io/es-secrets"

	TimeFilter         = "_g=(time:(from:now-24h,to:now))"
	FlowsDashboardName = "Tigera Secure EE Flow Logs"
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

	csrRootCAConfigMapName = "elasticsearch-config"
)

// Certificate management constants.
const (
	// Volume that is added by ECK and is overridden if certificate management is used.
	csrVolumeNameHTTP = "elastic-internal-http-certificates"
	// Volume that is added by ECK and is overridden if certificate management is used.
	csrVolumeNameTransport = "elastic-internal-transport-certificates"
	// Volume name that is added by ECK for the purpose of mounting certs.
	caVolumeName = "elasticsearch-certs"
)

var log = logf.Log.WithName("render")

// Elasticsearch renders the
func LogStorage(cfg *ElasticsearchConfiguration) Component {

	var kibanaSecrets []*corev1.Secret

	if cfg.KibanaCertSecret != nil {

		kibanaSecrets = append(kibanaSecrets, secret.CopyToNamespace(KibanaNamespace, cfg.KibanaCertSecret)...)

		if cfg.Installation.CertificateManagement != nil {

			kibanaSecrets = append(kibanaSecrets,
				CreateCertificateSecret(cfg.Installation.CertificateManagement.CACert, relasticsearch.InternalCertSecret, KibanaNamespace),
				CreateCertificateSecret(cfg.Installation.CertificateManagement.CACert, KibanaInternalCertSecret, common.OperatorNamespace()))
		} else if cfg.KibanaInternalCertSecret != nil {
			//copy the valid cert to operator namespace.
			kibanaSecrets = append(kibanaSecrets, secret.CopyToNamespace(common.OperatorNamespace(), cfg.KibanaInternalCertSecret)...)
		}
	}

	return &elasticsearchComponent{
		cfg:           cfg,
		kibanaSecrets: kibanaSecrets,
	}
}

// ElasticsearchConfiguration contains all the config information needed to render the component.
type ElasticsearchConfiguration struct {
	LogStorage                  *operatorv1.LogStorage
	Installation                *operatorv1.InstallationSpec
	ManagementCluster           *operatorv1.ManagementCluster
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	Elasticsearch               *esv1.Elasticsearch
	Kibana                      *kbv1.Kibana
	ClusterConfig               *relasticsearch.ClusterConfig
	ElasticsearchSecrets        []*corev1.Secret
	KibanaCertSecret            *corev1.Secret
	KibanaInternalCertSecret    *corev1.Secret
	PullSecrets                 []*corev1.Secret
	Provider                    operatorv1.Provider
	CuratorSecrets              []*corev1.Secret
	ESService                   *corev1.Service
	KbService                   *corev1.Service
	ClusterDomain               string
	DexCfg                      DexRelyingPartyConfig
	ElasticLicenseType          ElasticsearchLicenseType
}

type elasticsearchComponent struct {
	cfg             *ElasticsearchConfiguration
	kibanaSecrets   []*corev1.Secret
	esImage         string
	esOperatorImage string
	kibanaImage     string
	curatorImage    string
	csrImage        string
}

func (es *elasticsearchComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := es.cfg.Installation.Registry
	path := es.cfg.Installation.ImagePath
	prefix := es.cfg.Installation.ImagePrefix
	var err error
	es.esImage, err = components.GetReference(components.ComponentElasticsearch, reg, path, prefix, is)
	errMsgs := make([]string, 0)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	es.esOperatorImage, err = components.GetReference(components.ComponentElasticsearchOperator, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	es.kibanaImage, err = components.GetReference(components.ComponentKibana, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	es.curatorImage, err = components.GetReference(components.ComponentEsCurator, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if es.cfg.Installation.CertificateManagement != nil {
		es.csrImage, err = ResolveCSRInitImage(es.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (es *elasticsearchComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (es *elasticsearchComponent) Objects() ([]client.Object, []client.Object) {
	var toCreate, toDelete []client.Object

	// Doesn't matter what the cluster type is, if LogStorage exists and the DeletionTimestamp is set finalized the
	// deletion
	if es.cfg.LogStorage != nil && es.cfg.LogStorage.DeletionTimestamp != nil {

		if es.cfg.Elasticsearch != nil {
			if es.cfg.Elasticsearch.DeletionTimestamp == nil {
				toDelete = append(toDelete, es.cfg.Elasticsearch)
			}
		}

		if es.cfg.Kibana != nil {
			if es.cfg.Kibana.DeletionTimestamp == nil {
				toDelete = append(toDelete, es.cfg.Kibana)
			}
		}

		return toCreate, toDelete
	}

	if es.cfg.ManagementClusterConnection == nil {

		// ECK CRs
		toCreate = append(toCreate,
			CreateNamespace(ECKOperatorNamespace, es.cfg.Installation.KubernetesProvider),
		)

		toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(ECKOperatorNamespace, es.cfg.PullSecrets...)...)...)

		toCreate = append(toCreate,
			es.eckOperatorClusterRole(),
			es.eckOperatorClusterRoleBinding(),
			es.eckOperatorServiceAccount(),
		)
		// This is needed for the operator to be able to set privileged mode for pods.
		// https://docs.docker.com/ee/ucp/authorization/#secure-kubernetes-defaults
		if es.cfg.Provider == operatorv1.ProviderDockerEE {
			toCreate = append(toCreate, es.eckOperatorClusterAdminClusterRoleBinding())
		}

		// Apply the pod security policies for all providers except OpenShift
		if es.cfg.Provider != operatorv1.ProviderOpenShift {
			toCreate = append(toCreate,
				es.eckOperatorPodSecurityPolicy(),
				es.elasticsearchClusterRoleBinding(),
				es.elasticsearchClusterRole(),
				es.elasticsearchPodSecurityPolicy(),
				es.kibanaClusterRoleBinding(),
				es.kibanaClusterRole(),
				es.kibanaPodSecurityPolicy())
		}

		toCreate = append(toCreate, es.eckOperatorStatefulSet())

		// Elasticsearch CRs
		toCreate = append(toCreate, CreateNamespace(ElasticsearchNamespace, es.cfg.Installation.KubernetesProvider))

		if len(es.cfg.PullSecrets) > 0 {
			toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(ElasticsearchNamespace, es.cfg.PullSecrets...)...)...)
		}

		if len(es.cfg.ElasticsearchSecrets) > 0 {
			toCreate = append(toCreate, secret.ToRuntimeObjects(es.cfg.ElasticsearchSecrets...)...)
		}

		toCreate = append(toCreate, es.elasticsearchServiceAccount())
		toCreate = append(toCreate, es.cfg.ClusterConfig.ConfigMap())

		secureSettings := es.secureSettingsSecret()
		if len(secureSettings.Data) > 0 {
			toCreate = append(toCreate, secureSettings)
		}

		toCreate = append(toCreate, es.elasticsearchCluster(len(secureSettings.Data) > 0))

		// Kibana CRs
		toCreate = append(toCreate, CreateNamespace(KibanaNamespace, es.cfg.Installation.KubernetesProvider))
		toCreate = append(toCreate, es.kibanaServiceAccount())

		if len(es.cfg.PullSecrets) > 0 {
			toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(KibanaNamespace, es.cfg.PullSecrets...)...)...)
		}

		if len(es.kibanaSecrets) > 0 {
			toCreate = append(toCreate, secret.ToRuntimeObjects(es.kibanaSecrets...)...)
		}

		toCreate = append(toCreate, es.kibanaCR())

		// Curator CRs
		// If we have the curator secrets then create curator
		if len(es.cfg.CuratorSecrets) > 0 {
			toCreate = append(toCreate, secret.ToRuntimeObjects(secret.CopyToNamespace(ElasticsearchNamespace, es.cfg.CuratorSecrets...)...)...)
			toCreate = append(toCreate, es.esCuratorServiceAccount())

			// If the provider is not OpenShift apply the pod security policy for the curator.
			if es.cfg.Provider != operatorv1.ProviderOpenShift {
				toCreate = append(toCreate,
					es.curatorClusterRole(),
					es.curatorClusterRoleBinding(),
					es.curatorPodSecurityPolicy())
			}

			toCreate = append(toCreate, es.curatorCronJob())
		}

		toCreate = append(toCreate, es.oidcUserRole())
		toCreate = append(toCreate, es.oidcUserRoleBinding())

		// If we converted from a ManagedCluster to a Standalone or Management then we need to delete the elasticsearch
		// service as it differs between these cluster types
		if es.cfg.ESService != nil && es.cfg.ESService.Spec.Type == corev1.ServiceTypeExternalName {
			toDelete = append(toDelete, es.cfg.ESService)
		}

		if es.cfg.KbService != nil && es.cfg.KbService.Spec.Type == corev1.ServiceTypeExternalName {
			toDelete = append(toDelete, es.cfg.KbService)
		}
	} else {
		toCreate = append(toCreate,
			CreateNamespace(ElasticsearchNamespace, es.cfg.Installation.KubernetesProvider),
			es.elasticsearchExternalService(),
		)
	}

	if es.supportsOIDC() {
		toCreate = append(toCreate, secret.ToRuntimeObjects(es.cfg.DexCfg.RequiredSecrets(ElasticsearchNamespace)...)...)
	}

	if es.cfg.Installation.CertificateManagement != nil {
		toCreate = append(toCreate, CSRClusterRoleBinding("tigera-elasticsearch", ElasticsearchNamespace))
		toCreate = append(toCreate, CSRClusterRoleBinding("tigera-kibana", KibanaNamespace))
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
			Name:      ESGatewayServiceName,
			Namespace: ElasticsearchNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: fmt.Sprintf("%s.%s.svc.%s", GuardianServiceName, GuardianNamespace, es.cfg.ClusterDomain),
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
					"storage": resource.MustParse(fmt.Sprintf("%dGi", DefaultElasticStorageGi)),
				},
			},
			StorageClassName: &es.cfg.LogStorage.Spec.StorageClassName,
		},
	}

	// If the user has provided resource requirements, then use the user overrides instead
	if es.cfg.LogStorage.Spec.Nodes != nil && es.cfg.LogStorage.Spec.Nodes.ResourceRequirements != nil {
		userOverrides := *es.cfg.LogStorage.Spec.Nodes.ResourceRequirements
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
	if es.supportsOIDC() {
		volumeMounts = append(volumeMounts, es.cfg.DexCfg.RequiredVolumeMounts()...)
	}

	esContainer := corev1.Container{
		Name: "elasticsearch",
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				Exec: &corev1.ExecAction{
					Command: []string{"/readiness-probe"},
				},
			},
			FailureThreshold:    3,
			InitialDelaySeconds: 10,
			PeriodSeconds:       5,
			SuccessThreshold:    1,
			TimeoutSeconds:      5,
		},
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
		VolumeMounts: volumeMounts,
	}

	// For OpenShift, set the user to run as non-root specifically. This prevents issues with the elasticsearch
	// image which requires that root users have permissions to run CHROOT which is not given in OpenShift.
	if es.cfg.Provider == operatorv1.ProviderOpenShift {
		esContainer.SecurityContext = &corev1.SecurityContext{
			RunAsUser: ptr.Int64ToPtr(1000),
		}
	}

	// If the user has provided resource requirements, then use the user overrides instead
	if es.cfg.LogStorage.Spec.Nodes != nil && es.cfg.LogStorage.Spec.Nodes.ResourceRequirements != nil {
		userOverrides := *es.cfg.LogStorage.Spec.Nodes.ResourceRequirements
		esContainer.Resources = overrideResourceRequirements(esContainer.Resources, userOverrides)
	}

	// https://www.elastic.co/guide/en/elasticsearch/reference/current/vm-max-map-count.html
	initOSSettingsContainer := corev1.Container{
		Name: "elastic-internal-init-os-settings",
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.BoolToPtr(true),
			RunAsUser:  ptr.Int64ToPtr(0),
		},
		Image: es.esImage,
		Command: []string{
			"/bin/sh",
		},
		Args: []string{
			"-c",
			"echo 262144 > /proc/sys/vm/max_map_count",
		},
	}

	initContainers := []corev1.Container{initOSSettingsContainer}

	annotations := map[string]string{
		ElasticsearchTLSHashAnnotation: rmeta.SecretsAnnotationHash(es.cfg.ElasticsearchSecrets...),
	}
	if es.supportsOIDC() {
		initKeystore := corev1.Container{
			Name:  "elastic-internal-init-keystore",
			Image: es.esImage,
			SecurityContext: &corev1.SecurityContext{
				Privileged: ptr.BoolToPtr(false),
			},
			Command: []string{"/usr/bin/env", "bash", "-c", keystoreInitScript},
			VolumeMounts: []corev1.VolumeMount{{
				Name:      keystoreInitVolumeName,
				MountPath: keystoreInitMountPath,
				ReadOnly:  true,
			}},
		}
		initContainers = append(initContainers, initKeystore)
		annotations = es.cfg.DexCfg.RequiredAnnotations()
	}

	var volumes []corev1.Volume

	if es.supportsOIDC() {
		volumes = es.cfg.DexCfg.RequiredVolumes()
	}

	var autoMountToken bool
	if es.cfg.Installation.CertificateManagement != nil {

		// If certificate management is used, we need to override a mounting options for this init container.
		initFSName := "elastic-internal-init-filesystem"
		initFSContainer := corev1.Container{
			Name:  initFSName,
			Image: es.esImage,
			SecurityContext: &corev1.SecurityContext{
				Privileged: ptr.BoolToPtr(false),
			},
			Command: []string{"bash", "-c", "mkdir /mnt/elastic-internal/transport-certificates/ && touch /mnt/elastic-internal/transport-certificates/$HOSTNAME.tls.key && /mnt/elastic-internal/scripts/prepare-fs.sh"},
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{
					"cpu":    resource.MustParse("100m"),
					"memory": resource.MustParse("50Mi"),
				},
				Requests: corev1.ResourceList{
					"cpu":    resource.MustParse("100m"),
					"memory": resource.MustParse("50Mi"),
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				// Create transport mount, such that ECK will not auto-fill this with a secret volume.
				{
					Name:      csrVolumeNameTransport,
					MountPath: "/csr",
					ReadOnly:  false,
				},
			},
		}

		// Add the init container that will issue a CSR for HTTP traffic and mount it in an emptyDir.
		csrInitContainerHTTP := CreateCSRInitContainer(
			es.cfg.Installation.CertificateManagement,
			es.csrImage,
			csrVolumeNameHTTP,
			ElasticsearchServiceName,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
			dns.GetServiceDNSNames(ElasticsearchServiceName, ElasticsearchNamespace, es.cfg.ClusterDomain),
			ElasticsearchNamespace)
		csrInitContainerHTTP.Name = "key-cert-elastic"

		// Add the init container that will issue a CSR for transport and mount it in an emptyDir.
		csrInitContainerTransport := CreateCSRInitContainer(
			es.cfg.Installation.CertificateManagement,
			es.csrImage,
			csrVolumeNameTransport,
			ElasticsearchServiceName,
			"transport.tls.key",
			"transport.tls.crt",
			dns.GetServiceDNSNames(ElasticsearchServiceName, ElasticsearchNamespace, es.cfg.ClusterDomain),
			ElasticsearchNamespace)
		csrInitContainerTransport.Name = "key-cert-elastic-transport"

		initContainers = append(
			initContainers,
			initFSContainer,
			csrInitContainerHTTP,
			csrInitContainerTransport)

		volumes = append(volumes,
			corev1.Volume{
				Name: csrVolumeNameHTTP,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				}},
			corev1.Volume{
				Name: csrVolumeNameTransport,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				}},
		)
		// Make the pod mount the serviceaccount token of tigera-elasticsearch. On behalf of it, CSRs will be submitted.
		autoMountToken = true
		volumes = append(volumes, corev1.Volume{
			Name: csrRootCAConfigMapName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: csrRootCAConfigMapName},
				},
			},
		})
		esContainer.VolumeMounts = append(esContainer.VolumeMounts,
			corev1.VolumeMount{MountPath: CSRCMountPath, Name: csrVolumeNameHTTP, ReadOnly: false},
			corev1.VolumeMount{MountPath: "/usr/share/elasticsearch/config/http-certs", Name: csrVolumeNameHTTP, ReadOnly: false},
			corev1.VolumeMount{MountPath: "/usr/share/elasticsearch/config/transport-certs", Name: csrVolumeNameTransport, ReadOnly: false},
			corev1.VolumeMount{MountPath: "/usr/share/elasticsearch/config/node-transport-cert", Name: csrVolumeNameTransport, ReadOnly: false},
		)
	}

	// Init container that logs the SELinux context of the `/usr/share/elasticsearch` folder.
	// This init container is added as a workaround for a bug where Elasticsearch fails to starts when
	// under some scenarios Kuberentes starts the main container before all the init containers have
	// completed, SELinux is also enabled on the node, and Kubernetes/kubelet is using the Docker runtime.
	//
	// When SELinux is enabled, SELinux policy only allows a container to read a file/folder when their
	// SELinux labels match or when the mounts are configured to be shared among mutliple containers (the
	// latter isn't used by Kubernetes). These SELinux labels are managed by the container runtime.
	// This assignement of SELinux labels and relabelling of files/folders happen when the container is started.
	// The container runtime also assigns the same SELinux labels to containers created within the same sandbox.
	// The exception to this SELinux label assignement being when a container is privileged, the Docker runtime
	// mounts the container's files/folders with a different SELinux label than the one used for the sandbox.
	//
	// In Kubernetes, pods are created within the same sandbox. This ensures that files/folders can be shared by
	// containers running in the same pod. Kubernetes also explicitly requests relabelling of SELinux labels so
	// that any mounted file/folder gets the right SELinux labels.
	//
	// The bug manifests on a SELinux enabled node, when the main container starts before the privileged container
	// is complete. The main Elasticsearch container fails to read/write files on the shared volume mounts because
	// the privileged container is the last init container to start and it uses different SELinux labels
	// than the rest of the containers in the shared (pod) sandbox.
	//
	// Adding this additional init container after the privileged init container ensures that the volume mounts
	// always get the correct SELinux labels and guarantees the labels will be correct for the main container.

	initLogContextContainer := corev1.Container{
		Name: "elastic-internal-init-log-selinux-context",
		SecurityContext: &corev1.SecurityContext{
			Privileged: ptr.BoolToPtr(false),
		},
		Image: es.esImage,
		Command: []string{
			"/bin/sh",
		},
		Args: []string{
			"-c",
			"ls -ldZ /usr/share/elasticsearch",
		},
	}
	initContainers = append(initContainers, initLogContextContainer)

	// default to controlPlaneNodeSelector unless DataNodeSelector is set
	nodeSels := es.cfg.Installation.ControlPlaneNodeSelector
	if es.cfg.LogStorage.Spec.DataNodeSelector != nil {
		nodeSels = es.cfg.LogStorage.Spec.DataNodeSelector
	}

	podTemplate := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			InitContainers:               initContainers,
			Containers:                   []corev1.Container{esContainer},
			ImagePullSecrets:             secret.GetReferenceList(es.cfg.PullSecrets),
			NodeSelector:                 nodeSels,
			Tolerations:                  es.cfg.Installation.ControlPlaneTolerations,
			ServiceAccountName:           "tigera-elasticsearch",
			Volumes:                      volumes,
			AutomountServiceAccountToken: &autoMountToken,
		},
	}

	return podTemplate
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
			Image:   es.esImage,
			HTTP: cmnv1.HTTPConfig{
				TLS: cmnv1.TLSOptions{
					Certificate: cmnv1.SecretRef{
						SecretName: TigeraElasticsearchInternalCertSecret,
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

	if es.supportsOIDC() {
		secureSettings["xpack.security.authc.realms.oidc.oidc1.rp.client_secret"] = es.cfg.DexCfg.ClientSecret()
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
	nodeConfig := es.cfg.LogStorage.Spec.Nodes
	pvcTemplate := es.pvcTemplate()

	if nodeConfig == nil {
		// If we return a nil nodesets, this means the generated ElasticSearch CR will not be valid
		// and thus will fail validation on create. It will result in a degraded state visible to the user.
		// Note that we default spec.Nodes on create, so we shouldn't ever hit this branch in practice!
		log.Info("missing required field: logStorage.Spec.Nodes")
		return nil
	}

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
	if es.supportsOIDC() {
		config["xpack.security.authc.realms.oidc.oidc1"] = map[string]interface{}{
			"order":                       1,
			"rp.client_id":                DexClientId,
			"op.jwkset_path":              es.cfg.DexCfg.JWKSURI(),
			"op.userinfo_endpoint":        es.cfg.DexCfg.UserInfoURI(),
			"op.token_endpoint":           es.cfg.DexCfg.TokenURI(),
			"claims.principal":            es.cfg.DexCfg.UsernameClaim(),
			"claims.groups":               DefaultGroupsClaim,
			"rp.response_type":            "code",
			"rp.requested_scopes":         []string{"openid", "email", "profile", "groups", "offline_access"},
			"rp.redirect_uri":             fmt.Sprintf("%s/tigera-kibana/api/security/oidc/callback", es.cfg.DexCfg.BaseURL()),
			"rp.post_logout_redirect_uri": fmt.Sprintf("%s/tigera-kibana/logged_out", es.cfg.DexCfg.BaseURL()),
			"op.issuer":                   es.cfg.DexCfg.Issuer(),
			"op.authorization_endpoint":   fmt.Sprintf("%s/dex/auth", es.cfg.DexCfg.BaseURL()),
			"ssl.certificate_authorities": []string{"/usr/share/elasticsearch/config/dex/tls-dex.crt"},
		}
	}

	if es.cfg.Installation.CertificateManagement != nil {
		config["xpack.security.http.ssl.certificate_authorities"] = []string{"/usr/share/elasticsearch/config/http-certs/ca.crt"}
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
			APIGroups: []string{"agent.k8s.elastic.co"},
			Resources: []string{"agents", "agents/status", "agents/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"maps.k8s.elastic.co"},
			Resources: []string{"elasticmapsservers", "elasticmapsservers/status", "elasticmapsservers/finalizers"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
		{
			APIGroups: []string{"associations.k8s.elastic.co"},
			Resources: []string{"apmserverelasticsearchassociations", "apmserverelasticsearchassociations/status"},
			Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
		},
	}

	if es.cfg.Provider != operatorv1.ProviderOpenShift {
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
	memoryLimit := resource.Quantity{}
	memoryRequest := resource.Quantity{}
	for _, c := range es.cfg.LogStorage.Spec.ComponentResources {
		if c.ComponentName == operatorv1.ComponentNameECKOperator {
			memoryLimit = c.ResourceRequirements.Limits[corev1.ResourceMemory]
			memoryRequest = c.ResourceRequirements.Requests[corev1.ResourceMemory]
		}
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
					DNSPolicy:          corev1.DNSClusterFirst,
					ServiceAccountName: "elastic-operator",
					ImagePullSecrets:   secret.GetReferenceList(es.cfg.PullSecrets),
					HostNetwork:        false,
					NodeSelector:       es.cfg.Installation.ControlPlaneNodeSelector,
					Tolerations:        es.cfg.Installation.ControlPlaneTolerations,
					Containers: []corev1.Container{{
						Image: es.esOperatorImage,
						Name:  "manager",
						// Verbosity level of logs. -2=Error, -1=Warn, 0=Info, 0 and above=Debug
						Args: []string{
							"manager",
							"--log-verbosity=0",
							"--metrics-port=0",
							"--container-registry=" + es.cfg.Installation.Registry,
							"--max-concurrent-reconciles=3",
							"--ca-cert-validity=8760h",
							"--ca-cert-rotate-before=24h",
							"--cert-validity=8760h",
							"--cert-rotate-before=24h",
							"--enable-webhook=false",
							"--manage-webhook-certs=false",
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
							{Name: "OPERATOR_IMAGE", Value: es.esOperatorImage},
						},
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								"cpu":    resource.MustParse("1"),
								"memory": memoryLimit,
							},
							Requests: corev1.ResourceList{
								"cpu":    resource.MustParse("100m"),
								"memory": memoryRequest,
							},
						},
					}},
					TerminationGracePeriodSeconds: &gracePeriod,
				},
			},
		},
	}
}

func (es elasticsearchComponent) eckOperatorPodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	psp := podsecuritypolicy.NewBasePolicy()
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
			"defaultRoute":    fmt.Sprintf(KibanaDefaultRoute, TimeFilter, url.PathEscape(FlowsDashboardName)),
		},
		"elasticsearch.ssl.certificateAuthorities": []string{"/usr/share/kibana/config/elasticsearch-certs/tls.crt"},
		"tigera": map[string]interface{}{
			"enabled":        true,
			"licenseEdition": "enterpriseEdition",
		},
	}

	if es.supportsOIDC() {
		config["xpack.security.authc.providers"] = []string{"oidc", "basic"}
		config["xpack.security.authc.oidc.realm"] = "oidc1"
		config["server.xsrf.whitelist"] = []string{"/api/security/oidc/initiate_login"}
	}

	var initContainers []corev1.Container
	var volumes []corev1.Volume
	var automountToken bool
	var volumeMounts []corev1.VolumeMount
	if es.cfg.Installation.CertificateManagement != nil {
		config["elasticsearch.ssl.certificateAuthorities"] = []string{"/mnt/elastic-internal/http-certs/ca.crt"}
		automountToken = true
		csrInitContainer := CreateCSRInitContainer(
			es.cfg.Installation.CertificateManagement,
			es.csrImage,
			csrVolumeNameHTTP,
			ElasticsearchServiceName,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
			dns.GetServiceDNSNames(KibanaServiceName, KibanaNamespace, es.cfg.ClusterDomain),
			KibanaNamespace)

		initContainers = append(initContainers, csrInitContainer)
		volumeMounts = append(volumeMounts, corev1.VolumeMount{

			Name:      csrVolumeNameHTTP,
			MountPath: "/mnt/elastic-internal/http-certs/",
		})
		volumes = append(volumes,
			corev1.Volume{
				Name: csrVolumeNameHTTP,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			// Volume where we place the ca cert.
			corev1.Volume{
				Name: caVolumeName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{}}})
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
			Image:   es.kibanaImage,
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
					Annotations: map[string]string{
						KibanaTLSAnnotationHash: rmeta.SecretsAnnotationHash(es.kibanaSecrets...),
					},
					Labels: map[string]string{
						"name":    KibanaName,
						"k8s-app": KibanaName,
					},
				},
				Spec: corev1.PodSpec{
					ImagePullSecrets:             secret.GetReferenceList(es.cfg.PullSecrets),
					ServiceAccountName:           "tigera-kibana",
					NodeSelector:                 es.cfg.Installation.ControlPlaneNodeSelector,
					Tolerations:                  es.cfg.Installation.ControlPlaneTolerations,
					InitContainers:               initContainers,
					AutomountServiceAccountToken: &automountToken,
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
						VolumeMounts: volumeMounts,
					}},
					Volumes: volumes,
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
						Spec: relasticsearch.PodSpecDecorate(corev1.PodSpec{
							NodeSelector: es.cfg.Installation.ControlPlaneNodeSelector,
							Tolerations:  es.cfg.Installation.ControlPlaneTolerations,
							Containers: []corev1.Container{
								relasticsearch.ContainerDecorate(corev1.Container{
									Name:          EsCuratorName,
									Image:         es.curatorImage,
									Env:           es.curatorEnvVars(),
									LivenessProbe: elasticCuratorLivenessProbe,
									SecurityContext: &corev1.SecurityContext{
										RunAsNonRoot:             &t,
										AllowPrivilegeEscalation: &f,
									},
								}, DefaultElasticsearchClusterName, ElasticsearchCuratorUserSecret, es.cfg.ClusterDomain, es.SupportedOSType()),
							},
							ImagePullSecrets:   secret.GetReferenceList(es.cfg.PullSecrets),
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
		{Name: "EE_FLOWS_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*es.cfg.LogStorage.Spec.Retention.Flows)},
		{Name: "EE_AUDIT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*es.cfg.LogStorage.Spec.Retention.AuditReports)},
		{Name: "EE_SNAPSHOT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*es.cfg.LogStorage.Spec.Retention.Snapshots)},
		{Name: "EE_COMPLIANCE_REPORT_INDEX_RETENTION_PERIOD", Value: fmt.Sprint(*es.cfg.LogStorage.Spec.Retention.ComplianceReports)},
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
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(EsCuratorName)
	return psp
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
	psp := podsecuritypolicy.NewBasePolicy()
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
	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName("tigera-kibana")
	return psp
}

func (es *elasticsearchComponent) supportsOIDC() bool {
	return (es.cfg.ElasticLicenseType == ElasticsearchLicenseTypeEnterpriseTrial ||
		es.cfg.ElasticLicenseType == ElasticsearchLicenseTypeEnterprise) &&
		es.cfg.DexCfg != nil
}

func (es elasticsearchComponent) oidcUserRole() client.Object {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsManagerRole,
			Namespace: ElasticsearchNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				ResourceNames: []string{OIDCUsersConfigMapName},
				Verbs:         []string{"update", "patch"},
			},
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{OIDCUsersEsSecreteName},
				Verbs:         []string{"get", "list"},
			},
		},
	}
}

func (es elasticsearchComponent) oidcUserRoleBinding() client.Object {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsManagerRoleBinding,
			Namespace: ElasticsearchNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     EsManagerRole,
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ManagerServiceAccount,
				Namespace: ManagerNamespace,
			},
		},
	}
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
