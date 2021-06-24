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
	DeploymentName          = "tigera-es-gateway"
	ServiceAccountName      = "tigera-es-gateway"
	RoleName                = "tigera-es-gateway"
	VolumeName              = "tigera-es-gateway-certs"
	ElasticsearchUserSecret = "tigera-es-gateway-elasticsearch-access"
	TLSSecret               = "tigera-es-gateway-tls"
	PortName                = "es-gateway-port"
	Port                    = 5554

	ElasticsearchHTTPSEndpoint = "https://tigera-secure-internal-es-http.tigera-elasticsearch.svc:9200"
	ElasticsearchPort          = 9200
	KibanaHTTPSEndpoint        = "https://tigera-secure-internal-kb-http.tigera-kibana.svc:5601"
	KibanaPort                 = 5601
)

func EsGateway(
	logStorage *operatorv1.LogStorage,
	installation *operatorv1.InstallationSpec,
	pullSecrets []*corev1.Secret,
	esAdminUserSecret *corev1.Secret,
	kibanaInternalCertSecret *corev1.Secret,
	clusterDomain string,
) render.Component {
	var secrets []*corev1.Secret
	esGatewayTLSAnnotations := map[string]string{}

	// tigera-es-gateway-elasticsearch-access
	if esAdminUserSecret != nil {
		elasticsearchUserSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ElasticsearchUserSecret,
				Namespace: render.ElasticsearchNamespace,
			},
			Data: map[string][]byte{
				"username": []byte("elastic"),
				"password": esAdminUserSecret.Data["elastic"],
			},
		}
		secrets = append(secrets, elasticsearchUserSecret)
	}

	// tigera-secure-elasticsearch-cert should now exists in Operator and ES NS since LogStorage is rendered first.
	// Same with tigera-secure-es-http-certs-public

	// tigera-es-gateway-tls
	//TLSSecrets = append(TLSSecrets, TLSSecret)
	//TLSSecrets = append(TLSSecrets, secret.CopyToNamespace(render.ElasticsearchNamespace, TLSSecret)...)
	//esGatewayTLSAnnotations[tlsSecretHashAnnotation] = rmeta.AnnotationHash(TLSSecret.Data)
	//
	//cert := TLSSecret.Data[corev1.TLSCertKey]
	//
	//// tigera-secure-es-http-certs-public
	//esGatewayElasticCertSecret := TLSSecret.DeepCopy()
	//esGatewayElasticCertSecret.ObjectMeta = metav1.ObjectMeta{Name: relasticsearch.PublicCertSecret, Namespace: rmeta.OperatorNamespace()}
	//esGatewayElasticCertSecret.Data = map[string][]byte{corev1.TLSCertKey: cert}
	//TLSSecrets = append(TLSSecrets, esGatewayElasticCertSecret)
	//TLSSecrets = append(TLSSecrets, secret.CopyToNamespace(render.ElasticsearchNamespace, esGatewayElasticCertSecret)...)
	//esGatewayTLSAnnotations[render.ElasticsearchTLSHashAnnotation] = rmeta.SecretsAnnotationHash(esGatewayElasticCertSecret, esAdminUserSecret)
	//
	//// tigera-secure-kb-http-certs-public
	//esGatewayKibanaTLSSecret := esGatewayElasticCertSecret.DeepCopy()
	//esGatewayKibanaTLSSecret.ObjectMeta = metav1.ObjectMeta{Name: render.KibanaPublicCertSecret, Namespace: rmeta.OperatorNamespace()}
	//TLSSecrets = append(TLSSecrets, esGatewayKibanaTLSSecret)
	//TLSSecrets = append(TLSSecrets, secret.CopyToNamespace(render.KibanaNamespace, esGatewayKibanaTLSSecret)...)

	// tigera-secure-internal-kb-http-certs-public, mounted by ES Gateway.
	secrets = append(secrets, secret.CopyToNamespace(render.ElasticsearchNamespace, kibanaInternalCertSecret)...)
	esGatewayTLSAnnotations[render.KibanaTLSAnnotationHash] = rmeta.SecretsAnnotationHash(kibanaInternalCertSecret)
	return &esGateway{
		logStorage:              logStorage,
		installation:            installation,
		pullSecrets:             pullSecrets,
		secrets:                 secrets,
		esGatewayTLSAnnotations: esGatewayTLSAnnotations,
		clusterDomain:           clusterDomain,
	}
}

type esGateway struct {
	logStorage              *operatorv1.LogStorage
	installation            *operatorv1.InstallationSpec
	pullSecrets             []*corev1.Secret
	secrets                 []*corev1.Secret
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

	e.esGatewayImage, err = components.GetReference(components.ComponentESGateway, reg, path, prefix, is)
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

func (e *esGateway) Objects() (toCreate, toDelete []client.Object) {
	toCreate = append(toCreate, e.esGatewaySecrets()...)
	toCreate = append(toCreate, e.esGatewayElasticsearchService())
	toCreate = append(toCreate, e.esGatewayKibanaExternalService())
	toCreate = append(toCreate, e.esGatewayKibanaService())
	toCreate = append(toCreate, e.esGatewayRole())
	toCreate = append(toCreate, e.esGatewayRoleBinding())
	toCreate = append(toCreate, e.esGatewayServiceAccount())
	toCreate = append(toCreate, csrClusterRoleBinding(ServiceAccountName, render.ElasticsearchNamespace))
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
			Name:      RoleName,
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
			Name:      RoleName,
			Namespace: render.ElasticsearchNamespace,
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     RoleName,
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      ServiceAccountName,
				Namespace: render.ElasticsearchNamespace,
			},
		},
	}
}

func (e esGateway) esGatewayDeployment() *appsv1.Deployment {
	replicas := int32(2)

	envVars := []corev1.EnvVar{
		{Name: "ES_GATEWAY_LOG_LEVEL", Value: "INFO"},
		{Name: "ES_GATEWAY_ELASTIC_ENDPOINT", Value: ElasticsearchHTTPSEndpoint},
		{Name: "ES_GATEWAY_KIBANA_ENDPOINT", Value: KibanaHTTPSEndpoint},
		{Name: "ES_GATEWAY_HTTPS_CERT", Value: "/certs/https/tls.crt"},
		{Name: "ES_GATEWAY_HTTPS_KEY", Value: "/certs/https/tls.key"},
		{
			Name:      "ES_GATEWAY_ELASTIC_USERNAME",
			ValueFrom: secret.GetEnvVarSource(ElasticsearchUserSecret, "username", false),
		},
		{
			Name:      "ES_GATEWAY_ELASTIC_PASSWORD",
			ValueFrom: secret.GetEnvVarSource(ElasticsearchUserSecret, "password", false),
		},
	}

	dnsSvcNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, e.clusterDomain)
	dnsSvcNames = append(dnsSvcNames, dns.GetServiceDNSNames(render.KibanaServiceName, render.KibanaNamespace, e.clusterDomain)...)
	var initContainers []corev1.Container
	if e.installation.CertificateManagement != nil {
		initContainers = append(initContainers, render.CreateCSRInitContainer(
			e.installation.CertificateManagement,
			e.csrImage,
			render.TigeraElasticsearchCertSecret,
			render.ElasticsearchServiceName,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
			dnsSvcNames,
			render.ElasticsearchNamespace))
	}

	volumes := []corev1.Volume{
		{
			Name: VolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: render.TigeraElasticsearchCertSecret,
				},
			},
		},
		{
			Name: render.KibanaInternalCertSecret,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: render.KibanaInternalCertSecret,
				},
			},
		},
		{
			Name: relasticsearch.InternalCertSecret,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: relasticsearch.InternalCertSecret,
				},
			},
		},
	}

	volumeMounts := []corev1.VolumeMount{
		{Name: VolumeName, MountPath: "/certs/https", ReadOnly: true},
		{Name: render.KibanaInternalCertSecret, MountPath: "/certs/kibana", ReadOnly: true},
		{Name: relasticsearch.InternalCertSecret, MountPath: "/certs/elasticsearch", ReadOnly: true},
	}

	podTemplate := &corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeploymentName,
			Namespace: render.ElasticsearchNamespace,
			Labels: map[string]string{
				"k8s-app": DeploymentName,
			},
			Annotations: e.esGatewayTLSAnnotations,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: ServiceAccountName,
			ImagePullSecrets:   secret.GetReferenceList(e.pullSecrets),
			InitContainers:     initContainers,
			Volumes:            volumes,
			Containers: []corev1.Container{
				{
					Name:         DeploymentName,
					Image:        e.esGatewayImage,
					Env:          envVars,
					VolumeMounts: volumeMounts,
					ReadinessProbe: &corev1.Probe{
						Handler: corev1.Handler{
							HTTPGet: &corev1.HTTPGetAction{
								Path:   "/health",
								Port:   intstr.FromInt(Port),
								Scheme: corev1.URISchemeHTTPS,
							},
						},
						InitialDelaySeconds: 10,
						PeriodSeconds:       5,
					},
				},
			},
		},
	}
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DeploymentName,
			Namespace: render.ElasticsearchNamespace,
			Labels: map[string]string{
				"k8s-app": DeploymentName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": DeploymentName}},
			Template: *podTemplate,
			Replicas: &replicas,
		},
	}
}

func (e esGateway) esGatewayServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceAccountName,
			Namespace: render.ElasticsearchNamespace,
		},
	}
}

func (e esGateway) esGatewaySecrets() []client.Object {
	objs := []client.Object{}
	for _, s := range e.secrets {
		objs = append(objs, s)
	}
	return objs
}

func (e esGateway) esGatewayElasticsearchService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.ElasticsearchServiceName,
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": DeploymentName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       PortName,
					Port:       int32(ElasticsearchPort),
					TargetPort: intstr.FromInt(Port),
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
			Name:      render.KibanaServiceName,
			Namespace: render.KibanaNamespace,
		},
		Spec: corev1.ServiceSpec{
			Type:         corev1.ServiceTypeExternalName,
			ExternalName: fmt.Sprintf("%s.%s.svc.%s", render.KibanaServiceName, render.ElasticsearchNamespace, e.clusterDomain),
		},
	}
}

func (e esGateway) esGatewayKibanaService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      render.KibanaServiceName,
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": DeploymentName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       PortName,
					Port:       int32(KibanaPort),
					TargetPort: intstr.FromInt(Port),
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
