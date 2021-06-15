package esgateway

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	EsGatewayName                    = "tigera-es-gateway"
	EsGatewayServiceAccountName      = "tigera-es-gateway"
	EsGatewayRole                    = "tigera-es-gateway"
	EsGatewaySecretKeyName           = "key"
	EsGatewaySecretCertName          = "tls.crt"
	EsGatewayVolumeName              = "tigera-es-gateway-certs"
	EsGatewayElasticServiceName      = "tigera-secure-es-http"
	EsGatewayKibanaServiceName       = "tigera-secure-kb-http"
	EsGatewayKibanaPublicCertSecret  = "tigera-secure-kb-http-certs-public"
	EsGatewayElasticPublicCertSecret = "tigera-secure-es-http-certs-public"
	EsGatewayElasticUserSecret       = "tigera-es-gateway-elasticsearch-access"
	EsGatewayTLSSecret               = "tigera-es-gateway-tls"
	EsGatewayPortName                = "es-gateway-port"
	EsGatewayPort                    = 5554

	ElasticsearchHTTPSEndpoint = "https://tigera-secure-internal-es-http.tigera-elasticsearch.svc:9200"
	ElasticsearchPort          = 9200
	KibanaHTTPSEndpoint        = "https://tigera-secure-internal-kb-http.tigera-kibana.svc:5601"
	KibanaPort                 = 5601

	tlsSecretHashAnnotation = "hash.operator.tigera.io/tls-secret"
	elasticAnnotation       = "elasticsearch.k8s.elastic.co/cluster-name"
)

// ElasticsearchAdminUserSecret
// KibanaPublicCertSecret

func EsGateway(
	logStorage *operatorv1.LogStorage,
	installation *operatorv1.InstallationSpec,
	pullSecrets []*corev1.Secret,
	esAdminUserSecret *corev1.Secret,
	kibanaPublicCertSecret *corev1.Secret,
	esGatewayTLSSecret *corev1.Secret,
	clusterDomain string,
) render.Component {
	var esGatewayTLSSecrets []*corev1.Secret
	esGatewayTLSAnnotations := map[string]string{}

	// tigera-es-gateway-elasticsearch-access
	if esAdminUserSecret != nil {
		esGatewayElasticUserSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      EsGatewayElasticUserSecret,
				Namespace: render.ElasticsearchNamespace,
			},
			Data: map[string][]byte{
				"username": []byte("elastic"),
				"password": esAdminUserSecret.Data["elastic"],
			},
		}
		esGatewayTLSSecrets = append(esGatewayTLSSecrets, esGatewayElasticUserSecret)
	}

	// tigera-es-gateway-tls
	esGatewayTLSSecrets = append(esGatewayTLSSecrets, esGatewayTLSSecret)
	esGatewayTLSSecrets = append(esGatewayTLSSecrets, secret.CopyToNamespace(render.ElasticsearchNamespace, esGatewayTLSSecret)...)
	esGatewayTLSAnnotations[tlsSecretHashAnnotation] = rmeta.AnnotationHash(esGatewayTLSSecret.Data)

	cert := esGatewayTLSSecret.Data[EsGatewaySecretCertName]

	// tigera-secure-es-http-certs-public
	esGatewayElasticCertSecret := esGatewayTLSSecret.DeepCopy()
	esGatewayElasticCertSecret.ObjectMeta = metav1.ObjectMeta{Name: EsGatewayElasticPublicCertSecret, Namespace: rmeta.OperatorNamespace()}
	esGatewayElasticCertSecret.Data = map[string][]byte{EsGatewaySecretCertName: cert}
	esGatewayTLSSecrets = append(esGatewayTLSSecrets, esGatewayElasticCertSecret)
	esGatewayTLSSecrets = append(esGatewayTLSSecrets, secret.CopyToNamespace(render.ElasticsearchNamespace, esGatewayElasticCertSecret)...)
	esGatewayTLSAnnotations[render.ElasticsearchTLSHashAnnotation] = rmeta.SecretsAnnotationHash(esGatewayElasticCertSecret, esAdminUserSecret)

	// tigera-secure-kb-http-certs-public
	esGatewayKibanaTLSSecret := esGatewayElasticCertSecret.DeepCopy()
	esGatewayKibanaTLSSecret.ObjectMeta = metav1.ObjectMeta{Name: EsGatewayKibanaPublicCertSecret, Namespace: rmeta.OperatorNamespace()}
	esGatewayTLSSecrets = append(esGatewayTLSSecrets, esGatewayKibanaTLSSecret)
	esGatewayTLSSecrets = append(esGatewayTLSSecrets, secret.CopyToNamespace(render.KibanaNamespace, esGatewayKibanaTLSSecret)...)

	// tigera-secure-internal-kb-http-certs-public, mounted by ES Gateway.
	esGatewayTLSSecrets = append(esGatewayTLSSecrets, secret.CopyToNamespace(render.ElasticsearchNamespace, kibanaPublicCertSecret)...)
	esGatewayTLSAnnotations[render.KibanaTLSAnnotationHash] = rmeta.SecretsAnnotationHash(esGatewayKibanaTLSSecret, kibanaPublicCertSecret)
	return &esGateway{
		logStorage:              logStorage,
		installation:            installation,
		pullSecrets:             pullSecrets,
		esGatewayTLSSecrets:     esGatewayTLSSecrets,
		esGatewayTLSAnnotations: esGatewayTLSAnnotations,
		clusterDomain:           clusterDomain,
	}
}

type esGateway struct {
	logStorage              *operatorv1.LogStorage
	installation            *operatorv1.InstallationSpec
	pullSecrets             []*corev1.Secret
	esGatewayTLSSecrets     []*corev1.Secret
	esGatewayTLSAnnotations map[string]string
	clusterDomain           string
	csrImage                string
	esGatewayImage          string
}

func (e *esGateway) ResolveImages(is *operatorv1.ImageSet) error {
	reg := e.installation.Registry
	path := e.installation.ImagePath
	prefix := e.installation.ImagePrefix
	var err error
	errMsgs := []string{}

	e.esGatewayImage, err = components.GetReference(components.ComponentEsGateway, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}
	if e.installation.CertificateManagement != nil {
		e.csrImage, err = render.ResolveCSRInitImage(e.installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}
	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (e *esGateway) Objects() (objsToCreate, objsToDelete []client.Object) {
	var toCreate, toDelete []client.Object

	toCreate = append(toCreate, e.esGatewayTLSObjects()...)
	toCreate = append(toCreate, e.esGatewayElasticsearchService())
	toCreate = append(toCreate, e.esGatewayKibanaExternalService())
	toCreate = append(toCreate, e.esGatewayKibanaService())
	toCreate = append(toCreate, e.esGatewayRole())
	toCreate = append(toCreate, e.esGatewayRoleBinding())
	toCreate = append(toCreate, e.esGatewayServiceAccount())
	toCreate = append(toCreate, csrClusterRoleBinding(EsGatewayServiceAccountName, render.ElasticsearchNamespace))
	toCreate = append(toCreate, e.esGatewayDeployment())
	return toCreate, toDelete
}

func (e *esGateway) Ready() bool {
	return true
}

func (e *esGateway) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (e esGateway) esGatewayRole() *rbacv1.Role {
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{Kind: "Role", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsGatewayRole,
			Namespace: render.ElasticsearchNamespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{},
				Verbs:         []string{"get"},
			},
		},
	}
}

func (e esGateway) esGatewayRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsGatewayRole,
			Namespace: render.ElasticsearchNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     EsGatewayRole,
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      EsGatewayServiceAccountName,
				Namespace: render.ElasticsearchNamespace,
			},
		},
	}
}

func (e esGateway) esGatewayDeployment() *appsv1.Deployment {
	envVars := []corev1.EnvVar{
		{Name: "ES_GATEWAY_LOG_LEVEL", Value: "DEBUG"},
		{Name: "ES_GATEWAY_ELASTIC_ENDPOINT", Value: ElasticsearchHTTPSEndpoint},
		{Name: "ES_GATEWAY_KIBANA_ENDPOINT", Value: KibanaHTTPSEndpoint},
		{Name: "ES_GATEWAY_HTTPS_CERT", Value: "/certs/https/tls.crt"},
		{Name: "ES_GATEWAY_HTTPS_KEY", Value: "/certs/https/key"},
		{
			Name:      "ES_GATEWAY_ELASTIC_USERNAME",
			ValueFrom: secret.GetEnvVarSource(EsGatewayElasticUserSecret, "username", false),
		},
		{
			Name:      "ES_GATEWAY_ELASTIC_PASSWORD",
			ValueFrom: secret.GetEnvVarSource(EsGatewayElasticUserSecret, "password", false),
		},
	}

	dnsSvcNames := dns.GetServiceDNSNames(EsGatewayElasticServiceName, render.ElasticsearchNamespace, e.clusterDomain)
	dnsSvcNames = append(dnsSvcNames, dns.GetServiceDNSNames(EsGatewayKibanaServiceName, render.KibanaNamespace, e.clusterDomain)...)
	var initContainers []corev1.Container
	if e.installation.CertificateManagement != nil {
		initContainers = append(initContainers, render.CreateCSRInitContainer(
			e.installation.CertificateManagement,
			e.csrImage,
			EsGatewayTLSSecret,
			EsGatewayElasticServiceName,
			EsGatewaySecretKeyName,
			EsGatewaySecretCertName,
			dnsSvcNames,
			render.ElasticsearchNamespace))
	}

	volumes := []corev1.Volume{
		{
			Name: EsGatewayVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: EsGatewayTLSSecret,
				},
			},
		},
		{
			Name: render.KibanaPublicCertSecret,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: render.KibanaPublicCertSecret,
				},
			},
		},
		{
			Name: relasticsearch.PublicCertSecret,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: relasticsearch.PublicCertSecret,
				},
			},
		},
	}

	volumeMounts := []corev1.VolumeMount{
		{Name: EsGatewayVolumeName, MountPath: "/certs/https", ReadOnly: true},
		{Name: render.KibanaPublicCertSecret, MountPath: "/certs/kibana", ReadOnly: true},
		{Name: relasticsearch.PublicCertSecret, MountPath: "/certs/elasticsearch", ReadOnly: true},
	}

	annotations := map[string]string{}
	for k, v := range e.esGatewayTLSAnnotations {
		annotations[k] = v
	}
	annotations[elasticAnnotation] = "tigera-secure"

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsGatewayName,
			Namespace: render.ElasticsearchNamespace,
			Labels: map[string]string{
				"k8s-app": EsGatewayName,
			},
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: EsGatewayServiceAccountName,
			ImagePullSecrets:   secret.GetReferenceList(e.pullSecrets),
			InitContainers:     initContainers,
			Volumes:            volumes,
			Containers: []corev1.Container{
				{
					Name:         EsGatewayName,
					Image:        e.esGatewayImage,
					Env:          envVars,
					VolumeMounts: volumeMounts,
				},
			},
		},
	}
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsGatewayName,
			Namespace: render.ElasticsearchNamespace,
			Labels: map[string]string{
				"k8s-app": EsGatewayName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: e.logStorage.Spec.EsGatewayReplicaCount,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": EsGatewayName}},
			Template: *podTemplate,
		},
	}
}

func (e esGateway) esGatewayServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsGatewayServiceAccountName,
			Namespace: render.ElasticsearchNamespace,
		},
	}
}

func (e esGateway) esGatewayTLSObjects() []client.Object {
	objs := []client.Object{}
	for _, s := range e.esGatewayTLSSecrets {
		objs = append(objs, s)
	}
	return objs
}

func (e esGateway) esGatewayElasticsearchService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsGatewayElasticServiceName,
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": EsGatewayName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       EsGatewayPortName,
					Port:       int32(ElasticsearchPort),
					TargetPort: intstr.FromInt(EsGatewayPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

// In order to reach ES Gateway, components calling tigera-secure-kb-http.tigera-kibana.svc are redirected to
// tigera-secure-kb-http.tigera-elasticsearch.svc
func (e esGateway) esGatewayKibanaExternalService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsGatewayKibanaServiceName,
			Namespace: render.KibanaNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: fmt.Sprintf("%s.%s.svc.%s", EsGatewayKibanaServiceName, render.ElasticsearchNamespace, e.clusterDomain),
		},
	}
}

func (e esGateway) esGatewayKibanaService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      EsGatewayKibanaServiceName,
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": EsGatewayName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       EsGatewayPortName,
					Port:       int32(KibanaPort),
					TargetPort: intstr.FromInt(EsGatewayPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

// csrClusterRoleBinding returns a role binding with the necessary permissions to create certificate signing requests.
func csrClusterRoleBinding(name, namespace string) *rbacv1.ClusterRoleBinding {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   fmt.Sprintf("%s:csr-creator", name),
			Labels: map[string]string{},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     render.CSRClusterRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      name,
				Namespace: namespace,
			},
		},
	}
	return crb
}
