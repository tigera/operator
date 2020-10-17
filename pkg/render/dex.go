// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
//
package render

import (
	"fmt"
	"strconv"
	"strings"

	oprv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"gopkg.in/yaml.v2"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	// Manifest object variables
	DexNamespace     = "tigera-dex"
	DexObjectName    = "tigera-dex"
	DexPort          = 5556
	DexTLSSecretName = "tigera-dex-tls"

	// Various annotations to keep the pod up-to-date
	dexConfigAnnotation    = "hash.operator.tigera.io/tigera-dex-config"
	dexIdpSecretAnnotation = "hash.operator.tigera.io/tigera-idp-secret"
	dexSecretAnnotation    = "hash.operator.tigera.io/tigera-dex-secret"
	DexTLSSecretAnnotation = "hash.operator.tigera.io/tigera-dex-tls-secret"

	// Constants related to the idp secrets.
	OIDCSecretName               = "tigera-oidc-credentials"
	OpenshiftSecretName          = "tigera-openshift-credentials"
	ServiceAccountSecretField    = "serviceAccountSecret"
	ServiceAccountSecretLocation = "/etc/dex/secrets/google-groups.json"
	AdminEmailSecretField        = "adminEmail"
	RootCASecretField            = "rootCA"
	RootCASecretLocation         = "/etc/ssl/openshift.pem"
	ClientIDSecretField          = "clientID"
	ClientSecretSecretField      = "clientSecret"
	GoogleAdminEmailEnv          = "ADMIN_EMAIL"
	ClientIDEnv                  = "CLIENT_ID"
	ClientSecretEnv              = "CLIENT_SECRET"
	DexSecretEnv                 = "DEX_SECRET"

	// Constants related to Dex configurations
	DexClientId = "tigera-manager"
	DexCN       = "tigera-dex.tigera-dex.svc.cluster.local"

	DexJWKSURI = "https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys"
)

func Dex(
	authentication *oprv1.Authentication,
	pullSecrets []*corev1.Secret,
	openshift bool,
	installation *oprv1.Installation,
	tlsSecret *corev1.Secret,
	idpSecret *corev1.Secret,
	dexSecret *corev1.Secret,
) Component {

	if tlsSecret == nil {
		tlsSecret = dexTLSSecret()

	}

	if dexSecret == nil {
		dexSecret = dexClientSecret()

	}

	return &dexComponent{
		authentication: authentication,
		pullSecrets:    pullSecrets,
		openshift:      openshift,
		installation:   installation,
		tlsSecret:      tlsSecret,
		tlsSecretLocal: CopySecrets(DexNamespace, tlsSecret)[0],
		idpSecret:      idpSecret,
		dexSecret:      dexSecret,
		dexSecretLocal: CopySecrets(DexNamespace, dexSecret)[0],
		connector:      getConnector(authentication),
	}
}

type dexComponent struct {
	authentication *oprv1.Authentication
	pullSecrets    []*corev1.Secret
	openshift      bool
	installation   *oprv1.Installation
	tlsSecret      *corev1.Secret
	tlsSecretLocal *corev1.Secret
	idpSecret      *corev1.Secret
	dexSecret      *corev1.Secret
	dexSecretLocal *corev1.Secret
	connector      map[string]interface{}
}

func (es *dexComponent) SupportedOSType() OSType {
	return OSTypeLinux
}

func (c *dexComponent) Objects() ([]runtime.Object, []runtime.Object) {
	objs := []runtime.Object{
		createNamespace(DexNamespace, c.openshift),
		c.serviceAccount(),
		c.deployment(),
		c.service(),
		c.clusterRole(),
		c.clusterRoleBinding(),
		c.configMap(),
		c.idpSecret,
		c.tlsSecret,
		c.tlsSecretLocal,
		c.dexSecret,
		c.dexSecretLocal,
	}

	return objs, nil
}

// Method to satisfy the Component interface.
func (c *dexComponent) Ready() bool {
	return true
}

func (c *dexComponent) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: DexObjectName, Namespace: DexNamespace},
	}
}

func (c *dexComponent) clusterRole() runtime.Object {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DexObjectName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"dex.coreos.com"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
			{
				APIGroups: []string{"apiextensions.k8s.io"},
				Resources: []string{"customresourcedefinitions"},
				Verbs:     []string{"create"},
			},
		},
	}
}

func (c *dexComponent) clusterRoleBinding() runtime.Object {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: DexObjectName,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     DexObjectName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      DexObjectName,
				Namespace: DexNamespace,
			},
		},
	}
}

func (c *dexComponent) deployment() runtime.Object {

	volumeMounts := []corev1.VolumeMount{
		{
			Name:      "config",
			MountPath: "/etc/dex/cfg",
			ReadOnly:  true,
		},
		{
			Name:      "tls",
			MountPath: "/etc/dex/tls",
			ReadOnly:  true,
		},
	}

	if c.idpSecret.Data[ServiceAccountSecretField] != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "secrets",
			MountPath: "/etc/dex/secrets",
			ReadOnly:  true,
		})
	}

	if c.idpSecret.Data[RootCASecretField] != nil {
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      "secrets",
			MountPath: "/etc/ssl/",
			ReadOnly:  true,
		})
	}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexObjectName,
			Namespace: DexNamespace,
			Labels: map[string]string{
				"k8s-app": DexObjectName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": DexObjectName,
				},
			},
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      DexObjectName,
					Namespace: DexNamespace,
					Labels: map[string]string{
						"k8s-app": DexObjectName,
					},
					Annotations: dexAnnotations(c),
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.installation.Spec.ControlPlaneNodeSelector,
					ServiceAccountName: DexObjectName,
					Tolerations: []corev1.Toleration{
						{
							Key:               "node-role.kubernetes.io/master",
							Operator:          "",
							Value:             "",
							Effect:            corev1.TaintEffectNoSchedule,
							TolerationSeconds: nil,
						},
					},
					ImagePullSecrets: getImagePullSecretReferenceList(c.pullSecrets),
					Containers: []corev1.Container{
						{
							Name:            DexObjectName,
							Image:           components.GetReference(components.ComponentDex, c.installation.Spec.Registry, c.installation.Spec.ImagePath),
							Env:             c.env(),
							LivenessProbe:   c.probe(),
							SecurityContext: securityContext(),

							Command: []string{"/usr/local/bin/dex", "serve", "/etc/dex/cfg/config.yaml"},

							Ports: []corev1.ContainerPort{
								{
									Name:          "https",
									ContainerPort: DexPort,
								},
							},

							VolumeMounts: volumeMounts,
						},
					},
					Volumes: c.volumes(),
				},
			},
		},
	}
}

func (c *dexComponent) volumes() []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name:         "config",
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: DexObjectName}, Items: []corev1.KeyToPath{{Key: "config.yaml", Path: "config.yaml"}}}},
		},
		{
			Name:         "tls",
			VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: DexTLSSecretName}},
		},
	}
	if c.idpSecret.Data[ServiceAccountSecretField] != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name:         "secrets",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: c.idpSecret.Name, Items: []corev1.KeyToPath{{Key: ServiceAccountSecretField, Path: "google-groups.json"}}}},
			},
		)
	}
	if c.idpSecret.Data[RootCASecretField] != nil {
		volumes = append(volumes,
			corev1.Volume{
				Name:         "secrets",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: c.idpSecret.Name, Items: []corev1.KeyToPath{{Key: RootCASecretField, Path: "openshift.pem"}}}},
			},
		)
	}

	return volumes
}

func (c *dexComponent) service() runtime.Object {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexObjectName,
			Namespace: DexNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"k8s-app": DexObjectName,
			},
			Ports: []corev1.ServicePort{
				{
					Name: DexObjectName,
					Port: DexPort,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: DexPort,
					},
					Protocol: corev1.ProtocolTCP,
				},
			},
		},
	}
}

// Perform a HTTP GET to determine if an endpoint is available.
func (c *dexComponent) probe() *corev1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/dex/.well-known/openid-configuration",
				Port:   intstr.FromInt(DexPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

func (c *dexComponent) env() []corev1.EnvVar {
	env := []corev1.EnvVar{
		{Name: ClientIDEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: ClientIDSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: c.idpSecret.Name}}}},
		{Name: ClientSecretEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: c.idpSecret.Name}}}},
		{Name: DexSecretEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: ClientSecretSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: c.dexSecret.Name}}}},
	}

	if c.idpSecret.Data[ServiceAccountSecretField] != nil {
		env = append(env, corev1.EnvVar{Name: GoogleAdminEmailEnv, ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{Key: AdminEmailSecretField, LocalObjectReference: corev1.LocalObjectReference{Name: c.idpSecret.Name}}}})
	}

	return env

}

func (c *dexComponent) configMap() *corev1.ConfigMap {
	redirectURIs := []string{
		"https://localhost:9443/login/oidc/callback",
		"https://127.0.0.1:9443/login/oidc/callback",
		"https://localhost:9443/tigera-kibana/api/security/oidc/callback",
		"https://127.0.0.1:9443/tigera-kibana/api/security/oidc/callback",
	}
	host := c.authentication.Spec.ManagerDomain
	if host != "" && !strings.Contains(host, "localhost") && !strings.Contains(host, "127.0.0.1") {
		redirectURIs = append(redirectURIs, fmt.Sprintf("%s/login/oidc/callback", host))
		redirectURIs = append(redirectURIs, fmt.Sprintf("%s/tigera-kibana/api/security/oidc/callback", host))
	}

	data := map[string]interface{}{
		"issuer": fmt.Sprintf("%s/dex", c.authentication.Spec.ManagerDomain),
		"storage": map[string]interface{}{
			"type": "kubernetes",
			"config": map[string]bool{
				"inCluster": true,
			},
		},
		"web": map[string]interface{}{
			"https":                   "0.0.0.0:5556",
			"tlsCert":                 "/etc/dex/tls/tls.crt",
			"tlsKey":                  "/etc/dex/tls/tls.key",
			"allowedOrigins":          []string{"*"},
			"discoveryAllowedOrigins": []string{"*"},
		},
		"connectors": []map[string]interface{}{c.connector},
		"oauth2": map[string]interface{}{
			"skipApprovalScreen": true,
			"responseTypes":      []string{"id_token", "code", "token"},
		},
		"staticClients": []map[string]interface{}{
			{
				"id":           DexClientId,
				"redirectURIs": redirectURIs,
				"name":         "Calico Enterprise Manager",
				"secret":       fmt.Sprintf("$%s", DexSecretEnv),
			},
		},
	}

	bytes, err := yaml.Marshal(data)
	if err != nil { // Don't think this is possible.
		panic(err)
	}
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexObjectName,
			Namespace: DexNamespace,
		},
		Data: map[string]string{
			"config.yaml": string(bytes),
		},
	}
}

func dexAnnotations(c *dexComponent) map[string]string {
	var annotations = map[string]string{
		DexTLSSecretAnnotation: AnnotationHash(c.tlsSecret.Data),
		dexConfigAnnotation:    AnnotationHash(c.configMap()),
		dexIdpSecretAnnotation: AnnotationHash(c.idpSecret.Data),
		dexSecretAnnotation:    AnnotationHash(c.dexSecret.Data),
	}

	return annotations
}

// Append variables that are necessary for using the dex authenticator.
func AppendDexEnv(env []corev1.EnvVar, authentication *oprv1.Authentication, prefix string) []corev1.EnvVar {
	if authentication == nil {
		return append(env,
			corev1.EnvVar{Name: fmt.Sprintf("%sDEX_ENABLED", prefix), Value: strconv.FormatBool(false)})
	}

	usernameClaim := "email"
	groupsClaim := "groups"

	if authentication.Spec.OIDC != nil {
		usernameClaim = authentication.Spec.OIDC.UsernameClaim
		groupsClaim = authentication.Spec.OIDC.GroupsClaim
	}

	return append(env,
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_ENABLED", prefix), Value: strconv.FormatBool(true)},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_ISSUER", prefix), Value: fmt.Sprintf("%s/dex", authentication.Spec.ManagerDomain)},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_URL", prefix), Value: "https://tigera-dex.tigera-dex.svc.cluster.local:5556/"},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_JWKS_URL", prefix), Value: DexJWKSURI},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_CLIENT_ID", prefix), Value: DexClientId},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_USERNAME_CLAIM", prefix), Value: usernameClaim},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_GROUPS_CLAIM", prefix), Value: groupsClaim},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_USERNAME_PREFIX", prefix), Value: authentication.Spec.UsernamePrefix},
		corev1.EnvVar{Name: fmt.Sprintf("%sDEX_GROUPS_PREFIX", prefix), Value: authentication.Spec.GroupsPrefix})
}

// Add volume for Dex TLS secret.
func AppendDexVolume(volumes []corev1.Volume, authentication *oprv1.Authentication) []corev1.Volume {
	if authentication == nil {
		return volumes
	}
	return append(volumes, corev1.Volume{

		Name: DexTLSSecretName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: DexTLSSecretName,
				Items: []corev1.KeyToPath{
					{Key: "tls.crt", Path: "tls-dex.crt"},
				},
			},
		},
	})
}

// Add mount for ubi base image trusted cert location
func AppendDexVolumeMount(mounts []corev1.VolumeMount, authentication *oprv1.Authentication) []corev1.VolumeMount {
	if authentication == nil {
		return mounts
	}
	return append(mounts, corev1.VolumeMount{Name: DexTLSSecretName, MountPath: "/etc/ssl/certs"})
}

// This func prepares the configuration and objects that will be rendered related to the connector and its secrets.
func getConnector(authentication *oprv1.Authentication) map[string]interface{} {
	c := map[string]interface{}{}
	config := map[string]interface{}{
		"clientID":               fmt.Sprintf("$%s", ClientIDEnv),
		"clientSecret":           fmt.Sprintf("$%s", ClientSecretEnv),
		"redirectURI":            fmt.Sprintf("%s/dex/callback", authentication.Spec.ManagerDomain),
		"serviceAccountFilePath": ServiceAccountSecretLocation,
		"adminEmail":             fmt.Sprintf("$%s", GoogleAdminEmailEnv),
	}

	var typeid string
	var name string
	var issuer string

	oidc := authentication.Spec.OIDC
	if oidc != nil {
		issuer = oidc.IssuerURL
		if issuer == "https://accounts.google.com" {
			name = "Google"
			typeid = "google"
		} else {
			name = "OIDC"
			typeid = "oidc"
		}
		config["userNameKey"] = oidc.UsernameClaim
		config["userIDKey"] = oidc.UsernameClaim
	}

	if authentication.Spec.Openshift != nil {
		name = "Openshift"
		typeid = "openshift"
		issuer = authentication.Spec.Openshift.IssuerURL
		config[RootCASecretField] = RootCASecretLocation
	}

	c["type"] = typeid
	c["id"] = typeid
	c["name"] = name
	c["config"] = config
	config["issuer"] = issuer

	return c
}

func dexClientSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      DexObjectName,
			Namespace: OperatorNamespace(),
		},
		Data: map[string][]byte{
			ClientSecretSecretField: []byte(generatePassword(24)),
		},
	}
}
