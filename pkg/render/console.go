package render

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"

	crypto "github.com/openshift/library-go/pkg/crypto"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	managerPort           = 9443
	managerTargetPort     = 9443
	tigeraEsSecretName    = "tigera-es-config"
	managerNamespace      = "calico-monitoring"
	managerTlsSecretName  = "cnx-manager-tls"
	managerSecretKeyName  = "key"
	managerSecretCertName = "cert"
)

var operatorNamespace = "tigera-operator"

func Console(cr *operator.Installation, client client.Client) Component {
	if cr.Spec.Variant != operator.TigeraSecureEnterprise {
		return nil
	}
	v, ok := os.LookupEnv("OPERATOR_NAMESPACE")
	if ok {
		operatorNamespace = v
	}
	return &consoleComponent{cr: cr, client: client}
}

type consoleComponent struct {
	cr          *operator.Installation
	client      client.Client
	managerKey  []byte
	managerCert []byte
}

func (c *consoleComponent) GetObjects() []runtime.Object {
	key, cert, ok := readOperatorSecret(c.client)
	if !ok {
		return nil
	}
	objs := []runtime.Object{
		consoleManagerServiceAccount(),
		consoleManagerClusterRole(),
		consoleManagerClusterRoleBinding(),
	}
	key, cert, s := consoleOperatorSecret(key, cert)
	if key == nil || cert == nil {
		log.Info("Key or Cert not created")
		return nil
	}
	if s != nil {
		objs = append(objs, s)
	}
	objs = append(objs,
		consoleManagerCertificates(key, cert),
		consoleManagerDeployment(c.cr),
		consoleManagerService(c.cr),
		tigeraUserClusterRole(),
		tigeraNetworkAdminClusterRole(),
	)

	return objs
}

func (c *consoleComponent) GetComponentDeps() []runtime.Object {
	return nil
}

func (c *consoleComponent) Ready(client client.Client) bool {
	// Check that if the manager-tls secret exists that it is valid (has key and cert fields)
	// If it does not exist then this function still returns true
	_, err := validateManagerCertPair(client)
	if err != nil {
		log.Error(err, "Checking Ready for Console indicates error with Manager TLS Cert")
	}
	// TODO: When we have status I think if err != nil then we should be
	// reporting in status the the error.
	return err == nil
}

// consoleManagerDeployment creates a deployment for the Tigera Secure console manager component.
func consoleManagerDeployment(cr *operator.Installation) *appsv1.Deployment {
	var replicas int32 = 1

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cnx-manager",
			Namespace: managerNamespace,
			Labels: map[string]string{
				"k8s-app": "cnx-manager",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": "cnx-manager",
				},
			},
			Replicas: &replicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cnx-manager",
					Namespace: managerNamespace,
					Labels: map[string]string{
						"k8s-app": "cnx-manager",
					},
					Annotations: map[string]string{
						// Mark this pod as a critical add-on; when enabled, the critical add-on scheduler
						// reserves resources for critical add-on pods so that they can be rescheduled after
						// a failure.  This annotation works in tandem with the toleration below.
						"scheduler.alpha.kubernetes.io/critical-pod": "",
					},
				},
				Spec: corev1.PodSpec{
					NodeSelector: map[string]string{
						"beta.kubernetes.io/os": "linux",
					},
					ServiceAccountName: "cnx-manager",
					Tolerations:        consoleTolerations(),
					ImagePullSecrets:   cr.Spec.ImagePullSecrets,
					Containers: []corev1.Container{
						consoleManagerContainer(cr),
						consoleEsProxyContainer(cr),
						consoleProxyContainer(cr),
					},
					Volumes: consoleManagerVolumes(),
				},
			},
		},
	}
	return d
}

// consoleManagerVolumes returns the volumes for the Tigera Secure console component.
func consoleManagerVolumes() []v1.Volume {
	optional := true
	return []v1.Volume{
		{
			Name: managerTlsSecretName,
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: managerTlsSecretName,
				},
			},
		},
		{
			Name: "tigera-es-proxy-tls",
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: "tigera-es-config",
					Optional:   &optional,
					Items: []v1.KeyToPath{
						{Key: "tigera.elasticsearch.ca", Path: "ca.pem"},
					},
				},
			},
		},
	}
}

// consoleManagerProbe returns the probe for the manager container.
func consoleManagerProbe() *v1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/",
				Port:   intstr.FromInt(managerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

// consoleEsProxyProbe returns the probe for the ES proxy container.
func consoleEsProxyProbe() *v1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/tigera-elasticsearch/version",
				Port:   intstr.FromInt(managerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

// consoleProxyProbe returns the probe for the proxy container.
func consoleProxyProbe() *v1.Probe {
	return &corev1.Probe{
		Handler: corev1.Handler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   "/",
				Port:   intstr.FromInt(managerPort),
				Scheme: corev1.URISchemeHTTPS,
			},
		},
		InitialDelaySeconds: 90,
		PeriodSeconds:       10,
	}
}

// consoleManagerEnvVars returns the envvars for the console manager container.
func consoleManagerEnvVars(cr *operator.Installation) []v1.EnvVar {
	envs := []v1.EnvVar{
		{Name: "CNX_PROMETHEUS_API_URL", Value: "/api/v1/namespaces/calico-monitoring/services/calico-node-prometheus:9090/proxy/api/v1"},
		{Name: "CNX_COMPLIANCE_REPORTS_API_URL", Value: "/compliance/reports"},
		{Name: "CNX_QUERY_API_URL", Value: "/api/v1/namespaces/tigera-system/services/https:tigera-api:8080/proxy"},
		{Name: "CNX_ELASTICSEARCH_API_URL", Value: "/tigera-elasticsearch"},
		{Name: "CNX_ELASTICSEARCH_KIBANA_URL", Value: "http://127.0.0.1:30601"},
		{Name: "CNX_ENABLE_ERROR_TRACKING", Value: "false"},
		{Name: "CNX_ALP_SUPPORT", Value: "false"},
		{Name: "CNX_CLUSTER_NAME", Value: "cluster"},
	}

	envs = append(envs, consoleOAuth2EnvVars(cr)...)
	return envs
}

// consoleManagerContainer returns the manager container.
func consoleManagerContainer(cr *operator.Installation) corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		{Name: "tigera-es-proxy-tls", MountPath: "/etc/ssl/elastic/"},
	}
	return corev1.Container{
		Name:          "cnx-manager",
		Image:         cr.Spec.Components.Console.Manager.Image,
		Env:           consoleManagerEnvVars(cr),
		VolumeMounts:  volumeMounts,
		LivenessProbe: consoleManagerProbe(),
	}
}

// consoleOAuth2EnvVars returns the OAuth2/OIDC envvars depending on the authentication type.
func consoleOAuth2EnvVars(cr *operator.Installation) []v1.EnvVar {
	envs := []corev1.EnvVar{
		{Name: "CNX_WEB_AUTHENTICATION_TYPE", Value: string(cr.Spec.Components.Console.Auth.Type)},
	}

	switch cr.Spec.Components.Console.Auth.Type {
	case operator.AuthTypeOIDC:
		oidcEnvs := []corev1.EnvVar{
			{Name: "CNX_WEB_OIDC_AUTHORITY", Value: cr.Spec.Components.Console.Auth.Authority},
			{Name: "CNX_WEB_OIDC_CLIENT_ID", Value: cr.Spec.Components.Console.Auth.ClientID},
		}
		envs = append(envs, oidcEnvs...)
	case operator.AuthTypeOAuth:
		oauthEnvs := []corev1.EnvVar{
			{Name: "CNX_WEB_OAUTH_AUTHORITY", Value: cr.Spec.Components.Console.Auth.Authority},
			{Name: "CNX_WEB_OAUTH_CLIENT_ID", Value: cr.Spec.Components.Console.Auth.ClientID},
		}
		envs = append(envs, oauthEnvs...)
	}
	return envs
}

// consoleProxyContainer returns the container for the console proxy container.
func consoleProxyContainer(cr *operator.Installation) corev1.Container {
	return corev1.Container{
		Name:  "cnx-manager-proxy",
		Image: cr.Spec.Components.Console.Proxy.Image,
		Env:   consoleOAuth2EnvVars(cr),
		VolumeMounts: []corev1.VolumeMount{
			{Name: managerTlsSecretName, MountPath: "/etc/cnx-manager-web-tls"},
		},
		LivenessProbe: consoleProxyProbe(),
	}
}

// consoleEsProxyEnv returns the env vars for the ES proxy container.
func consoleEsProxyEnv() []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "info"},
		{
			Name:      "ELASTIC_HOST",
			ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.host"),
		},
		{
			Name:      "ELASTIC_PORT",
			ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.port"),
		},
		{
			Name:      "ELASTIC_ACCESS_MODE",
			ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.access-mode"),
		},
		{
			Name:      "ELASTIC_SCHEME",
			ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.scheme"),
		},
		// TODO: make this configurable?
		{
			Name: "ELASTIC_INSECURE_SKIP_VERIFY", Value: "false",
		},
		{
			Name:      "ELASTIC_USERNAME",
			ValueFrom: envVarSourceFromSecret(tigeraEsSecretName, "tigera.elasticsearch.username", Optional),
		},
		{
			Name:      "ELASTIC_PASSWORD",
			ValueFrom: envVarSourceFromSecret(tigeraEsSecretName, "tigera.elasticsearch.password", Optional),
		},
		{
			Name:      "ELASTIC_CA",
			ValueFrom: envVarSourceFromConfigmap(tigeraEsConfigMapName, "tigera.elasticsearch.ca.path"),
		},
	}
}

// consoleEsProxyContainer returns the ES proxy container
func consoleEsProxyContainer(cr *operator.Installation) corev1.Container {
	volumeMounts := []corev1.VolumeMount{
		{Name: "tigera-es-proxy-tls", MountPath: "/etc/ssl/elastic/"},
	}
	apiServer := corev1.Container{
		Name:          "tigera-es-proxy",
		Image:         cr.Spec.Components.Console.EsProxy.Image,
		Env:           consoleEsProxyEnv(),
		VolumeMounts:  volumeMounts,
		LivenessProbe: consoleEsProxyProbe(),
	}

	return apiServer
}

// consoleTolerations returns the tolerations for the Tigera Secure console deployment pods.
func consoleTolerations() []v1.Toleration {
	return []v1.Toleration{
		{
			Key:    "node-role.kubernetes.io/master",
			Effect: v1.TaintEffectNoSchedule,
		},
		// Allow this pod to be rescheduled while the node is in "critical add-ons only" mode.
		// This, along with the annotation above marks this pod as a critical add-on.
		{
			Key:      "CriticalAddonsOnly",
			Operator: v1.TolerationOpExists,
		},
	}
}

// consoleManagerService returns the service exposing the Tigera Secure web app.
func consoleManagerService(cr *operator.Installation) *v1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cnx-manager",
			Namespace: managerNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Port:       managerPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(managerTargetPort),
				},
			},
			Selector: map[string]string{
				"k8s-app": "cnx-manager",
			},
		},
	}
}

// consoleManagerServiceAccount creates the serviceaccount used by the Tigera Secure web app.
func consoleManagerServiceAccount() *v1.ServiceAccount {
	return &v1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "cnx-manager", Namespace: managerNamespace},
	}
}

// consoleManagerClusterRole returns a clusterrole that allows authn/authz review requests.
func consoleManagerClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "cnx-manager-role",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
		},
	}
}

// consoleManagerClusterRoleBinding returns a clusterrolebinding that gives the cnx-manager serviceaccount
// the permissions in the cnx-manager-role.
func consoleManagerClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "cnx-manager-binding"},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "cnx-manager-role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "cnx-manager",
				Namespace: managerNamespace,
			},
		},
	}
}

// validateManagerCertPair checks if the manager-tls secret exists and if so
// that it contains key and cert fields. If a secret exists then it is returned.
// If there is an error accessing the secret (except NotFound) or the cert
// does not have both a key and cert field then an appropriate error is returned.
// If no secret exists then nil, nil is returned to represent that no cert is valid.
func validateManagerCertPair(c client.Client) (*v1.Secret, error) {
	secret := &v1.Secret{}
	secretNamespacedName := types.NamespacedName{Name: "manager-tls", Namespace: operatorNamespace}
	err := c.Get(context.Background(), secretNamespacedName, secret)
	if err != nil {
		// If the reason for the error is not found then that is acceptable
		// so return valid in that case.
		statErr, ok := err.(*kerrors.StatusError)
		if ok && statErr.ErrStatus.Reason == metav1.StatusReasonNotFound {
			return nil, nil
		} else {
			return nil, fmt.Errorf("Failed to read manager cert from datastore: %s", err)
		}
	}

	if val, ok := secret.Data[managerSecretKeyName]; !ok || len(val) == 0 {
		return secret, fmt.Errorf("manager-tls Secret does not have a field named 'key'")
	}
	if val, ok := secret.Data[managerSecretCertName]; !ok || len(val) == 0 {
		return secret, fmt.Errorf("manager-tls Secret does not have a field named 'cert'")
	}

	return secret, nil
}

func readOperatorSecret(c client.Client) (key, cert []byte, ok bool) {
	secret, err := validateManagerCertPair(c)
	if err != nil {
		log.Error(err, "Failed to validate cert pair")
		return nil, nil, false
	}

	if secret != nil {
		key = secret.Data[managerSecretKeyName]
		cert = secret.Data[managerSecretCertName]
	}
	return key, cert, true
}

// consoleOperatorSecret if the key (k) or cert (c) passed in are empty
// then a new cert/key pair is created, they are returned as key/cert and a
// Secret secret is returned populated with the key/cert.
// If k,c are populated then this indicates the tigera-operator secret
// already exists so no new key/cert is created and no Secret is returned,
// but the passed in k,c values are returned as key,cert.
func consoleOperatorSecret(k, c []byte) (key, cert []byte, s *v1.Secret) {
	if len(k) != 0 && len(c) != 0 {
		// If the secret already exists in the operator NS then nothing to do,
		// so no need to return it to be created.
		return k, c, nil
	}

	log.Info("Creating self-signed certificate", managerTlsSecretName, managerTlsSecretName)
	// Create cert
	var err error
	key, cert, err = makeSignedCertKeyPair()
	if err != nil {
		log.Error(err, "Unable to create signed cert pair")
		return nil, nil, nil
	}

	data := make(map[string][]byte)
	data[managerSecretKeyName] = key
	data[managerSecretCertName] = cert
	return key, cert, &v1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "manager-tls",
			Namespace: operatorNamespace,
		},
		Data: data,
	}
}

// makeSignedCertKeyPair generates and returns a key pair for a self signed
// cert.
// This code came from:
// https://github.com/openshift/library-go/blob/84f02c4b7d6ab9d67f63b13586693600051de401/pkg/controller/controllercmd/cmd.go#L153
func makeSignedCertKeyPair() (key, cert []byte, err error) {
	temporaryCertDir, err := ioutil.TempDir("", "serving-cert-")
	if err != nil {
		return nil, nil, err
	}
	signerName := fmt.Sprintf("%s-signer@%d", "tigera-operator", time.Now().Unix())
	ca, err := crypto.MakeSelfSignedCA(
		filepath.Join(temporaryCertDir, "serving-signer.crt"),
		filepath.Join(temporaryCertDir, "serving-signer.key"),
		filepath.Join(temporaryCertDir, "serving-signer.serial"),
		signerName,
		0,
	)
	if err != nil {
		return nil, nil, err
	}

	// nothing can trust this, so we don't really care about hostnames
	servingCert, err := ca.MakeServerCert(sets.NewString("localhost"), 30)
	if err != nil {
		return nil, nil, err
	}
	crtContent := &bytes.Buffer{}
	keyContent := &bytes.Buffer{}
	if err := servingCert.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, nil, err
	}

	return keyContent.Bytes(), crtContent.Bytes(), nil
}

func consoleManagerCertificates(key, cert []byte) *v1.Secret {
	data := make(map[string][]byte)
	data[managerSecretKeyName] = key
	data[managerSecretCertName] = cert
	return &v1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      managerTlsSecretName,
			Namespace: managerNamespace,
		},
		Data: data,
	}
}

// tigeraUserClusterRole returns a cluster role for a default Tigera Secure user.
func tigeraUserClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-ui-user",
		},
		Rules: []rbacv1.PolicyRule{
			// List requests that the Tigera manager needs.
			{
				APIGroups: []string{
					"projectcalico.org",
					"networking.k8s.io",
					"extensions",
					"",
				},
				// Use both networkpolicies and tier.networkpolicies, and globalnetworkpolicies and tier.globalnetworkpolicies resource
				// types to ensure identical behavior irrespective of the Calico RBAC scheme (see the ClusterRole
				// "ee-calico-tiered-policy-passthru" for more details).
				Resources: []string{
					"tiers",
					"networkpolicies",
					"tier.networkpolicies",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"namespaces",
					"globalnetworksets",
				},
				Verbs: []string{"watch", "list"},
			},
			// Access to statistics.
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:tigera-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			// Access to flow logs, audit logs, and statistics
			{
				APIGroups: []string{"lma.tigera.io"},
				Resources: []string{"index"},
				ResourceNames: []string{
					"flows", "audit*", "events",
				},
				Verbs: []string{"get"},
			},
			// Access to policies in the default tier
			{
				APIGroups:     []string{"projectcalico.org"},
				Resources:     []string{"tiers"},
				ResourceNames: []string{"default"},
				Verbs:         []string{"get"},
			},
			// List and download the reports in the Tigera Secure console.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports"},
				Verbs:     []string{"get", "list"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreporttypes"},
				Verbs:     []string{"get"},
			},
		},
	}
}

// tigeraNetworkAdminClusterRole returns a cluster role for a Tigera Secure console network admin.
func tigeraNetworkAdminClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-network-admin",
		},
		Rules: []rbacv1.PolicyRule{
			// Full access to all network policies
			{
				APIGroups: []string{
					"projectcalico.org",
					"networking.k8s.io",
					"extensions",
				},
				// Use both networkpolicies and tier.networkpolicies, and globalnetworkpolicies and tier.globalnetworkpolicies resource
				// types to ensure identical behavior irrespective of the Calico RBAC scheme (see the ClusterRole
				// "ee-calico-tiered-policy-passthru" for more details).
				Resources: []string{
					"tiers",
					"networkpolicies",
					"tier.networkpolicies",
					"globalnetworkpolicies",
					"tier.globalnetworkpolicies",
					"globalnetworksets",
				},
				Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
			},
			// Additional "list" requests that the Tigera Secure console needs
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"watch", "list"},
			},
			// Access to statistics.
			{
				APIGroups: []string{""},
				Resources: []string{"services/proxy"},
				ResourceNames: []string{
					"https:tigera-api:8080", "calico-node-prometheus:9090",
				},
				Verbs: []string{"get", "create"},
			},
			// Access to flow logs, audit logs, and statistics
			{
				APIGroups: []string{"lma.tigera.io"},
				Resources: []string{"index"},
				ResourceNames: []string{
					"flows", "audit*", "events",
				},
				Verbs: []string{"get"},
			},
			// Manage globalreport configuration, view report generation status, and list reports in the Tigera Secure console.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports"},
				Verbs:     []string{"*"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports/status"},
				Verbs:     []string{"get", "list", "watch"},
			},
			// List and download the reports in the Tigera Secure console.
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"globalreports"},
				Verbs:     []string{"get"},
			},
		},
	}
}
