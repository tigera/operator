// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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
	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	DeploymentName        = "tigera-secure-es-gateway"
	ServiceAccountName    = "tigera-secure-es-gateway"
	RoleName              = "tigera-secure-es-gateway"
	VolumeName            = "tigera-secure-es-gateway-certs"
	ServiceName           = "tigera-secure-es-gateway-http"
	ElasticsearchPortName = "es-gateway-elasticsearch-port"
	KibanaPortName        = "es-gateway-kibana-port"
	Port                  = 5554

	ElasticsearchHTTPSEndpoint = "https://tigera-secure-es-http.tigera-elasticsearch.svc:9200"
	ElasticsearchPort          = 9200
	KibanaHTTPSEndpoint        = "https://tigera-secure-kb-http.tigera-kibana.svc:5601"
	KibanaPort                 = 5601
)

func EsGateway(c *Config) render.Component {
	var certSecretsESCopy []*corev1.Secret
	// Only render the public cert secret in the Operator namespace.
	secrets := []*corev1.Secret{c.CertSecrets[1]}

	// Copy the Operator namespaced cert secrets to the Elasticsearch namespace.
	certSecretsESCopy = append(certSecretsESCopy, secret.CopyToNamespace(render.ElasticsearchNamespace, c.CertSecrets...)...)
	tlsAnnotations := map[string]string{render.ElasticsearchTLSHashAnnotation: rmeta.SecretsAnnotationHash(append(certSecretsESCopy, c.EsInternalCertSecret)...)}

	secrets = append(secrets, certSecretsESCopy...)

	// tigera-secure-kb-http-certs-public, mounted by ES Gateway.
	secrets = append(secrets, secret.CopyToNamespace(render.ElasticsearchNamespace, c.KibanaInternalCertSecret)...)
	tlsAnnotations[render.KibanaTLSAnnotationHash] = rmeta.SecretsAnnotationHash(c.KibanaInternalCertSecret)

	secrets = append(secrets, c.KubeControllersUserSecrets...)

	return &esGateway{
		installation:    c.Installation,
		pullSecrets:     c.PullSecrets,
		secrets:         secrets,
		tlsAnnotations:  tlsAnnotations,
		clusterDomain:   c.ClusterDomain,
		esAdminUserName: c.EsAdminUserName,
	}
}

type esGateway struct {
	installation    *operatorv1.InstallationSpec
	pullSecrets     []*corev1.Secret
	secrets         []*corev1.Secret
	tlsAnnotations  map[string]string
	clusterDomain   string
	csrImage        string
	esGatewayImage  string
	esAdminUserName string
}

type Config struct {
	Installation               *operatorv1.InstallationSpec
	PullSecrets                []*corev1.Secret
	CertSecrets                []*corev1.Secret
	KubeControllersUserSecrets []*corev1.Secret
	KibanaInternalCertSecret   *corev1.Secret
	EsInternalCertSecret       *corev1.Secret
	ClusterDomain              string
	EsAdminUserName            string
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
	toCreate = append(toCreate, e.esGatewayService())
	toCreate = append(toCreate, e.esGatewayRole())
	toCreate = append(toCreate, e.esGatewayRoleBinding())
	toCreate = append(toCreate, e.esGatewayServiceAccount())
	toCreate = append(toCreate, e.esGatewayDeployment())
	if e.installation.CertificateManagement != nil {
		toCreate = append(toCreate, render.CSRClusterRoleBinding(RoleName, render.ElasticsearchNamespace))
	}
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
				Verbs:         []string{"get", "list", "watch"},
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
	envVars := []corev1.EnvVar{
		{Name: "ES_GATEWAY_LOG_LEVEL", Value: "INFO"},
		{Name: "ES_GATEWAY_ELASTIC_ENDPOINT", Value: ElasticsearchHTTPSEndpoint},
		{Name: "ES_GATEWAY_KIBANA_ENDPOINT", Value: KibanaHTTPSEndpoint},
		{Name: "ES_GATEWAY_HTTPS_CERT", Value: "/certs/https/tls.crt"},
		{Name: "ES_GATEWAY_HTTPS_KEY", Value: "/certs/https/tls.key"},
		{Name: "ES_GATEWAY_ELASTIC_USERNAME", Value: e.esAdminUserName},
		{Name: "ES_GATEWAY_ELASTIC_PASSWORD", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: render.ElasticsearchAdminUserSecret,
				},
				Key: e.esAdminUserName,
			},
		}},
	}

	certVolume := corev1.Volume{
		Name: VolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: render.TigeraElasticsearchCertSecret,
			},
		},
	}

	var initContainers []corev1.Container
	if e.installation.CertificateManagement != nil {
		svcDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, e.clusterDomain)
		svcDNSNames = append(svcDNSNames, dns.GetServiceDNSNames(ServiceName, render.ElasticsearchNamespace, e.clusterDomain)...)

		initContainers = append(initContainers, render.CreateCSRInitContainer(
			e.installation.CertificateManagement,
			e.csrImage,
			VolumeName,
			ServiceName,
			corev1.TLSPrivateKeyKey,
			corev1.TLSCertKey,
			svcDNSNames,
			render.ElasticsearchNamespace))

		certVolume.VolumeSource = corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}
	}

	volumes := []corev1.Volume{
		certVolume,
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
			Annotations: e.tlsAnnotations,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: ServiceAccountName,
			ImagePullSecrets:   secret.GetReferenceList(e.pullSecrets),
			Volumes:            volumes,
			InitContainers:     initContainers,
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

	if e.installation.ControlPlaneReplicas != nil && *e.installation.ControlPlaneReplicas > 1 {
		podTemplate.Spec.Affinity = podaffinity.NewPodAntiAffinity(DeploymentName, render.ElasticsearchNamespace)
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
			Replicas: e.installation.ControlPlaneReplicas,
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

func (e esGateway) esGatewayService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ServiceName,
			Namespace: render.ElasticsearchNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"k8s-app": DeploymentName},
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       ElasticsearchPortName,
					Port:       int32(ElasticsearchPort),
					TargetPort: intstr.FromInt(Port),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       KibanaPortName,
					Port:       int32(KibanaPort),
					TargetPort: intstr.FromInt(Port),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}
