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
	"fmt"
	"strings"

	cmneckalpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/common/v1alpha1"
	esalpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/elasticsearch/v1alpha1"
	kibanav1alpha1 "github.com/elastic/cloud-on-k8s/operators/pkg/apis/kibana/v1alpha1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/components"
	inf "gopkg.in/inf.v0"
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	ECKOperatorName      = "elastic-operator"
	ECKOperatorNamespace = "tigera-eck-operator"
	ECKWebhookSecretName = "webhook-server-secret"

	ElasticsearchStorageClass  = "tigera-elasticsearch"
	ElasticsearchNamespace     = "tigera-elasticsearch"
	ElasticsearchHTTPURL       = "tigera-secure-es-http.tigera-elasticsearch.svc"
	ElasticsearchHTTPSEndpoint = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
	ElasticsearchName          = "tigera-secure"
	ElasticsearchConfigMapName = "tigera-secure-elasticsearch"

	KibanaHTTPURL          = "tigera-secure-kb-http.tigera-kibana.svc"
	KibanaHTTPSEndpoint    = "https://tigera-secure-kb-http.tigera-kibana.svc:5601"
	KibanaName             = "tigera-secure"
	KibanaNamespace        = "tigera-kibana"
	KibanaPublicCertSecret = "tigera-secure-kb-http-certs-public"
	TigeraKibanaCertSecret = "tigera-secure-kibana-cert"
	KibanaDefaultCertPath  = "/etc/ssl/kibana/ca.pem"
	KibanaBasePath         = "tigera-kibana"

	DefaultElasticsearchClusterName = "cluster"
	DefaultElasticsearchReplicas    = 0
)

func Elasticsearch(
	logStorage *operatorv1.LogStorage,
	clusterConfig *ElasticsearchClusterConfig,
	esCertSecret *corev1.Secret,
	kibanaCertSecret *corev1.Secret,
	createWebhookSecret bool,
	pullSecrets []*corev1.Secret,
	provider operatorv1.Provider,
	registry string) (Component, error) {
	var esCertSecrets, kibanaCertSecrets []runtime.Object
	if esCertSecret == nil {
		var err error
		esCertSecret, err = createOperatorTLSSecret(nil,
			TigeraElasticsearchCertSecret,
			"tls.key",
			"tls.crt",
			DefaultCertificateDuration,
			nil, ElasticsearchHTTPURL,
		)
		if err != nil {
			return nil, err
		}
		esCertSecrets = []runtime.Object{esCertSecret}
	}

	if kibanaCertSecret == nil {
		var err error
		kibanaCertSecret, err = createOperatorTLSSecret(nil,
			TigeraKibanaCertSecret,
			"tls.key",
			"tls.crt",
			DefaultCertificateDuration,
			nil, KibanaHTTPURL,
		)
		if err != nil {
			return nil, err
		}
		kibanaCertSecrets = []runtime.Object{kibanaCertSecret}
	}

	esCertSecrets = append(esCertSecrets, secretsToRuntimeObjects(copySecrets(ElasticsearchNamespace, esCertSecret)...)...)
	kibanaCertSecrets = append(kibanaCertSecrets, secretsToRuntimeObjects(copySecrets(KibanaNamespace, kibanaCertSecret)...)...)
	return &elasticsearchComponent{
		logStorage:          logStorage,
		clusterConfig:       clusterConfig,
		esCertSecrets:       esCertSecrets,
		kibanaCertSecrets:   kibanaCertSecrets,
		createWebhookSecret: createWebhookSecret,
		pullSecrets:         pullSecrets,
		provider:            provider,
		registry:            registry,
	}, nil
}

type elasticsearchComponent struct {
	logStorage          *operatorv1.LogStorage
	clusterConfig       *ElasticsearchClusterConfig
	esCertSecrets       []runtime.Object
	kibanaCertSecrets   []runtime.Object
	createWebhookSecret bool
	pullSecrets         []*corev1.Secret
	provider            operatorv1.Provider
	registry            string
}

func (es *elasticsearchComponent) Objects() ([]runtime.Object, []runtime.Object) {
	var objs []runtime.Object
	objs = append(objs, es.eckOperator()...)
	objs = append(objs, createNamespace(ElasticsearchNamespace, es.provider == operatorv1.ProviderOpenShift))

	objs = append(objs, secretsToRuntimeObjects(copySecrets(ElasticsearchNamespace, es.pullSecrets...)...)...)
	objs = append(objs, es.esCertSecrets...)
	objs = append(objs, es.clusterConfig.ConfigMap())

	objs = append(objs, es.elasticsearchCluster())
	objs = append(objs, es.kibana()...)

	return objs, nil
}

func (es *elasticsearchComponent) Ready() bool {
	return true
}

// generate the PVC required for the Elasticsearch nodes
func (es elasticsearchComponent) pvcTemplate() corev1.PersistentVolumeClaim {
	storageClassName := ElasticsearchStorageClass
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
			StorageClassName: &storageClassName,
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

	podTemplate := corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{
			Containers:       []corev1.Container{esContainer},
			ImagePullSecrets: getImagePullSecretReferenceList(es.pullSecrets),
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
func (es elasticsearchComponent) elasticsearchCluster() *esalpha1.Elasticsearch {
	nodeConfig := es.logStorage.Spec.Nodes

	return &esalpha1.Elasticsearch{
		TypeMeta: metav1.TypeMeta{Kind: "Elasticsearch", APIVersion: "elasticsearch.k8s.elastic.co/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchName,
			Namespace: ElasticsearchNamespace,
			Annotations: map[string]string{
				"common.k8s.elastic.co/controller-version": components.VersionECKOperator,
			},
		},
		Spec: esalpha1.ElasticsearchSpec{
			Version: components.VersionECKElasticsearch,
			Image:   constructImage(ECKElasticsearchImageName, es.registry),
			HTTP: cmneckalpha1.HTTPConfig{
				TLS: cmneckalpha1.TLSOptions{
					Certificate: cmneckalpha1.SecretRef{
						SecretName: TigeraElasticsearchCertSecret,
					},
				},
			},
			Nodes: []esalpha1.NodeSpec{
				{
					NodeCount: int32(nodeConfig.Count),
					Config: &cmneckalpha1.Config{
						Data: map[string]interface{}{
							"node.master": "true",
							"node.data":   "true",
							"node.ingest": "true",
						},
					},
					VolumeClaimTemplates: []corev1.PersistentVolumeClaim{es.pvcTemplate()},
					PodTemplate:          es.podTemplate(),
				},
			},
		},
	}
}

func (es elasticsearchComponent) eckOperator() []runtime.Object {
	objs := []runtime.Object{
		createNamespace(ECKOperatorNamespace, es.provider == operatorv1.ProviderOpenShift),
		es.eckOperatorClusterRole(),
		es.eckOperatorClusterRoleBinding(),
		es.eckOperatorServiceAccount(),
	}

	// This is needed for the operator to be able to set privileged mode for pods.
	// https://docs.docker.com/ee/ucp/authorization/#secure-kubernetes-defaults
	if es.provider == operatorv1.ProviderDockerEE {
		objs = append(objs, es.eckOperatorClusterAdminClusterRoleBinding())
	}

	objs = append(objs, secretsToRuntimeObjects(copySecrets(ECKOperatorNamespace, es.pullSecrets...)...)...)
	if es.createWebhookSecret {
		objs = append(objs, es.eckOperatorWebhookSecret())
	}
	objs = append(objs, es.eckOperatorStatefulSet())

	return objs
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
				Resources: []string{"deployments"},
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

func (es elasticsearchComponent) eckOperatorStatefulSet() *apps.StatefulSet {
	gracePeriod := int64(10)
	defaultMode := int32(420)

	return &apps.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ECKOperatorName,
			Namespace: ECKOperatorNamespace,
			Labels: map[string]string{
				"control-plane": "elastic-operator",
				"k8s-app":       "elastic-operator",
			},
		},
		Spec: apps.StatefulSetSpec{
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
						Image: constructImage(ECKOperatorImageName, es.registry),
						Name:  "manager",
						Args:  []string{"manager", "--operator-roles", "all", "--enable-debug-logs=false"},
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
							{Name: "OPERATOR_IMAGE", Value: "docker.elastic.co/eck/eck-operator:0.9.0"},
						},
						Resources: corev1.ResourceRequirements{
							Limits: corev1.ResourceList{
								"cpu":    resource.MustParse("1"),
								"memory": resource.MustParse("150Mi"),
							},
							Requests: corev1.ResourceList{
								"cpu":    resource.MustParse("100m"),
								"memory": resource.MustParse("20Mi"),
							},
						},
						Ports: []corev1.ContainerPort{{
							ContainerPort: 9876,
							Name:          "webhook-server",
							Protocol:      corev1.ProtocolTCP,
						}},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "cert",
							MountPath: "/tmp/cert",
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

// Create resources needed to run a Kibana cluster (namespace, Kibana resource, secrets...)
func (es elasticsearchComponent) kibana() []runtime.Object {
	objs := []runtime.Object{createNamespace(KibanaNamespace, false)}
	objs = append(objs, secretsToRuntimeObjects(copySecrets(KibanaNamespace, es.pullSecrets...)...)...)
	objs = append(objs, es.kibanaCertSecrets...)
	objs = append(objs, es.kibanaCR())
	return objs
}

func (es elasticsearchComponent) kibanaCR() *kibanav1alpha1.Kibana {
	return &kibanav1alpha1.Kibana{
		ObjectMeta: metav1.ObjectMeta{
			Name:      KibanaName,
			Namespace: KibanaNamespace,
			Labels: map[string]string{
				"k8s-app": KibanaName,
			},
			Annotations: map[string]string{
				"common.k8s.elastic.co/controller-version": components.VersionECKOperator,
			},
		},
		Spec: kibanav1alpha1.KibanaSpec{
			Version: components.VersionECKKibana,
			Image:   constructImage(KibanaImageName, es.registry),
			Config: &cmneckalpha1.Config{
				Data: map[string]interface{}{
					"server": map[string]interface{}{
						"basePath":        fmt.Sprintf("/%s", KibanaBasePath),
						"rewriteBasePath": true,
					},
				},
			},
			NodeCount: 1,
			HTTP: cmneckalpha1.HTTPConfig{
				TLS: cmneckalpha1.TLSOptions{
					Certificate: cmneckalpha1.SecretRef{
						SecretName: TigeraKibanaCertSecret,
					},
				},
			},
			ElasticsearchRef: cmneckalpha1.ObjectSelector{
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
