package render

import (
	cmneckalpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1alpha1"
	eckv1alpha1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1alpha1"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/components"
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	ECKOperatorName           = "elastic-operator"
	ECKOperatorNamespace      = "tigera-eck-operator"
	ECKWebhookSecretName      = "webhook-server-secret"
	ElasticsearchStorageClass = "tigera-elasticsearch"
	ElasticsearchNamespace    = "tigera-elasticsearch"
	ElasticsearchClusterHTTP  = "tigera-secure-es-http.tigera-elasticsearch.svc"
	KibanaHTTP                = "https://tigera-secure-kb-http.tigera-kibana.svc:5601"
	ElasticsearchName         = "tigera-secure"
)

func Elasticsearch(logStorage *operatorv1.LogStorage, certSecret *corev1.Secret, openShift bool, registry string) (Component, error) {
	var certSecrets []runtime.Object
	if certSecret == nil {
		var err error
		certSecret, err = createOperatorTLSSecret(nil,
			TigeraElasticsearchCertSecret,
			"tls.key",
			"tls.crt",
			nil, ElasticsearchClusterHTTP,
		)
		if err != nil {
			return nil, err
		}
		certSecrets = []runtime.Object{certSecret}
	}

	certSecrets = append(certSecrets, copySecrets(ElasticsearchNamespace, certSecret)...)
	return &elasticsearchComponent{
		logStorage:  logStorage,
		certSecrets: certSecrets,
		openShift:   openShift,
		registry:    registry,
	}, nil
}

type elasticsearchComponent struct {
	logStorage  *operatorv1.LogStorage
	certSecrets []runtime.Object
	openShift   bool
	registry    string
}

func (es *elasticsearchComponent) Objects() []runtime.Object {
	var objs []runtime.Object
	objs = append(objs, es.eckOperator()...)
	objs = append(objs, createNamespace(ElasticsearchNamespace, es.openShift))

	objs = append(objs, es.certSecrets...)

	objs = append(objs, es.elasticsearchCluster())

	return objs
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
				Requests: corev1.ResourceList{
					"storage": resource.MustParse("10Gi"),
				},
			},
			StorageClassName: &storageClassName,
		},
	}

	// We only allow the user to overwrite the resource requirements for the pvc
	if es.logStorage.Spec.Nodes != nil && es.logStorage.Spec.Nodes.ResourceRequirements != nil {
		pvcTemplate.Spec.Resources = *es.logStorage.Spec.Nodes.ResourceRequirements
	}

	return pvcTemplate
}

// render the Elasticsearch CR that the ECK operator uses to create elasticsearch cluster
func (es elasticsearchComponent) elasticsearchCluster() *eckv1alpha1.Elasticsearch {
	nodeConfig := es.logStorage.Spec.Nodes

	return &eckv1alpha1.Elasticsearch{
		TypeMeta: metav1.TypeMeta{Kind: "Elasticsearch", APIVersion: "elasticsearch.k8s.elastic.co/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ElasticsearchName,
			Namespace: ElasticsearchNamespace,
			Annotations: map[string]string{
				"common.k8s.elastic.co/controller-version": components.VersionECKOperator,
			},
		},
		Spec: eckv1alpha1.ElasticsearchSpec{
			Version: components.VersionECKElasticsearch,
			Image:   constructImage(ECKElasticsearchImageName, es.registry),
			HTTP: cmneckalpha1.HTTPConfig{
				TLS: cmneckalpha1.TLSOptions{
					Certificate: cmneckalpha1.SecretRef{
						SecretName: TigeraElasticsearchCertSecret,
					},
				},
			},
			Nodes: []eckv1alpha1.NodeSpec{
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
				},
			},
		},
	}
}

func (es elasticsearchComponent) eckOperator() []runtime.Object {

	return []runtime.Object{
		createNamespace(ECKOperatorNamespace, es.openShift),
		es.eckOperatorWebhookSecret(),
		es.eckOperatorClusterRole(),
		es.eckOperatorClusterRoleBinding(),
		es.eckOperatorServiceAccount(),
		es.eckOperatorStatefulSet(),
	}
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

func (es elasticsearchComponent) eckOperatorServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ECKOperatorName,
			Namespace: ECKOperatorNamespace,
		},
	}
}

func (es elasticsearchComponent) eckOperatorStatefulSet() *apps.StatefulSet {
	cpu1, _ := resource.ParseQuantity("1")
	cpu2, _ := resource.ParseQuantity("100m")
	mem1, _ := resource.ParseQuantity("100Mi")
	mem2, _ := resource.ParseQuantity("20Mi")
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
								"cpu":    cpu1,
								"memory": mem1,
							},
							Requests: corev1.ResourceList{
								"cpu":    cpu2,
								"memory": mem2,
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
