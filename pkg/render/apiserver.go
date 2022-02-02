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

package render

import (
	"fmt"
	"strings"

	"github.com/tigera/operator/pkg/render/common/podaffinity"
	"github.com/tigera/operator/pkg/render/common/podsecuritycontext"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	apiregv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/ptr"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/secret"
)

const (
	apiServerPort           = 5443
	queryServerPort         = 8080
	APIServerSecretKeyName  = "apiserver.key"
	APIServerSecretCertName = "apiserver.crt"
)

// The following functions are helpers for determining resource names based on
// the configured product variant.
func ProjectCalicoApiServerTLSSecretName(v operatorv1.ProductVariant) string {
	if v == operatorv1.Calico {
		return "calico-apiserver-certs"
	}
	return "tigera-apiserver-certs"
}

func ProjectCalicoApiServerServiceName(v operatorv1.ProductVariant) string {
	if v == operatorv1.Calico {
		return "calico-api"
	}
	return "tigera-api"
}

func serviceAccountName(v operatorv1.ProductVariant) string {
	if v == operatorv1.Calico {
		return "calico-apiserver"
	}
	return "tigera-apiserver"
}

func csrRolebindingName(v operatorv1.ProductVariant) string {
	if v == operatorv1.Calico {
		return "calico-apiserver"
	}
	return "tigera-apiserver"
}

func APIServer(cfg *APIServerConfiguration) (Component, error) {

	tlsSecrets := []*corev1.Secret{}
	tlsHashAnnotations := make(map[string]string)

	if cfg.Installation.CertificateManagement == nil {
		tlsHashAnnotations[TlsSecretHashAnnotation] = rmeta.AnnotationHash(cfg.TLSKeyPair.Data)

		copy := cfg.TLSKeyPair.DeepCopy()
		copy.ObjectMeta = metav1.ObjectMeta{
			Name:      ProjectCalicoApiServerTLSSecretName(cfg.Installation.Variant),
			Namespace: rmeta.APIServerNamespace(cfg.Installation.Variant),
		}
		tlsSecrets = append(tlsSecrets, copy)
	}

	if cfg.ManagementCluster != nil {
		if cfg.TunnelCASecret == nil {
			cfg.TunnelCASecret = voltronTunnelSecret()
			tlsSecrets = append(tlsSecrets, cfg.TunnelCASecret)
		}
		tlsSecrets = append(tlsSecrets, secret.CopyToNamespace(rmeta.APIServerNamespace(cfg.Installation.Variant), cfg.TunnelCASecret)...)
		tlsHashAnnotations[voltronTunnelHashAnnotation] = rmeta.AnnotationHash(cfg.TunnelCASecret.Data)
	}

	return &apiServerComponent{
		cfg:            cfg,
		tlsSecrets:     tlsSecrets,
		tlsAnnotations: tlsHashAnnotations,
	}, nil
}

// APIServerConfiguration contains all the config information needed to render the component.
type APIServerConfiguration struct {
	K8SServiceEndpoint          k8sapi.ServiceEndpoint
	Installation                *operatorv1.InstallationSpec
	ForceHostNetwork            bool
	ManagementCluster           *operatorv1.ManagementCluster
	ManagementClusterConnection *operatorv1.ManagementClusterConnection
	AmazonCloudIntegration      *operatorv1.AmazonCloudIntegration
	TLSKeyPair                  *corev1.Secret
	PullSecrets                 []*corev1.Secret
	Openshift                   bool
	TunnelCASecret              *corev1.Secret
	ClusterDomain               string
}

type apiServerComponent struct {
	cfg              *APIServerConfiguration
	tlsSecrets       []*corev1.Secret
	tlsAnnotations   map[string]string
	isManagement     bool
	apiServerImage   string
	queryServerImage string
	certSignReqImage string
}

func (c *apiServerComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		c.apiServerImage, err = components.GetReference(components.ComponentAPIServer, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
		c.queryServerImage, err = components.GetReference(components.ComponentQueryServer, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	} else {
		c.apiServerImage, err = components.GetReference(components.ComponentCalicoAPIServer, reg, path, prefix, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if c.cfg.Installation.CertificateManagement != nil {
		c.certSignReqImage, err = ResolveCSRInitImage(c.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (c *apiServerComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func populateLists(create []client.Object, dels []client.Object, f func() (client.Object, client.Object)) ([]client.Object, []client.Object) {
	c, d := f()
	create = append(create, c)
	dels = append(dels, d)
	return create, dels
}

func (c *apiServerComponent) Objects() ([]client.Object, []client.Object) {
	// Start with all of the cluster-scoped resources that are used for both Calico and Calico Enterprise.
	// When switching between Calico / Enterprise, these objects are simply updated in-place.
	globalObjects := []client.Object{
		c.calicoCustomResourcesClusterRole(),
		c.calicoCustomResourcesClusterRoleBinding(),
	}

	// These objects are global, and have different names based on Calico or Calico Enterprise.
	// We need to delete the object for the variant that we're not currently installilng.
	objsToDelete := []client.Object{}
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.delegateAuthClusterRoleBinding)
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.authClusterRole)
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.authClusterRoleBinding)
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.authReaderRoleBinding)
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.webhookReaderClusterRole)
	globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.webhookReaderClusterRoleBinding)
	if !c.cfg.Openshift {
		globalObjects, objsToDelete = populateLists(globalObjects, objsToDelete, c.apiServerPodSecurityPolicy)
	}

	// Namespaced objects that are common between Calico and Calico Enterprise. They don't need to be explicitly
	// deleted, since they will be garbage collected on namespace deletion.
	namespacedObjects := []client.Object{}
	// Add in image pull secrets.
	secrets := secret.CopyToNamespace(rmeta.APIServerNamespace(c.cfg.Installation.Variant), c.cfg.PullSecrets...)
	namespacedObjects = append(namespacedObjects, secret.ToRuntimeObjects(secrets...)...)

	namespacedObjects = append(namespacedObjects,
		c.apiServerServiceAccount(),
		c.apiServerDeployment(),
		c.apiServerService(),
	)

	// Add in certificates for API server TLS.
	if c.cfg.Installation.CertificateManagement == nil {
		namespacedObjects = append(namespacedObjects, c.getTLSObjects()...)
		globalObjects = append(globalObjects, c.apiServiceRegistration(c.cfg.TLSKeyPair.Data[APIServerSecretCertName]))
	} else {
		namespacedObjects = append(namespacedObjects, c.apiServiceRegistration(c.cfg.Installation.CertificateManagement.CACert))
		globalObjects = append(globalObjects, CSRClusterRoleBinding(csrRolebindingName(c.cfg.Installation.Variant), rmeta.APIServerNamespace(c.cfg.Installation.Variant)))
	}

	// Global enterprise-only objects.
	globalEnterpriseObjects := []client.Object{
		CreateNamespace(rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise), c.cfg.Installation.KubernetesProvider),
		c.tigeraCustomResourcesClusterRole(),
		c.tigeraCustomResourcesClusterRoleBinding(),
		c.tierGetterClusterRole(),
		c.kubeControllerMgrTierGetterClusterRoleBinding(),
		c.uisettingsgroupGetterClusterRole(),
		c.kubeControllerMgrUisettingsgroupGetterClusterRoleBinding(),
		c.tigeraUserClusterRole(),
		c.tigeraNetworkAdminClusterRole(),
		c.tieredPolicyPassthruClusterRole(),
		c.tieredPolicyPassthruClusterRolebinding(),
		c.uiSettingsPassthruClusterRole(),
		c.uiSettingsPassthruClusterRolebinding(),
	}

	// Namespaced enterprise-only objects.
	namespacedEnterpriseObjects := []client.Object{
		c.auditPolicyConfigMap(),
	}

	// Global OSS-only objects.
	globalCalicoObjects := []client.Object{
		CreateNamespace(rmeta.APIServerNamespace(operatorv1.Calico), c.cfg.Installation.KubernetesProvider),
	}

	// Compile the final arrays based on the variant.
	objsToCreate := []client.Object{}
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		// Create any enterprise specific objects.
		globalObjects = append(globalObjects, globalEnterpriseObjects...)
		namespacedObjects = append(namespacedObjects, namespacedEnterpriseObjects...)

		// Explicitly delete any global OSS objects.
		// Namespaced objects will be handled by namespace deletion.
		objsToDelete = append(objsToDelete, globalCalicoObjects...)
	} else {
		// Create any Calico-only objects
		globalObjects = append(globalObjects, globalCalicoObjects...)

		// Add in a NetworkPolicy.
		namespacedObjects = append(namespacedObjects, c.networkPolicy())

		// Explicitly delete any global enterprise objects.
		// Namespaced objects will be handled by namespace deletion.
		objsToDelete = append(objsToDelete, globalEnterpriseObjects...)
	}

	objsToCreate = append(globalObjects, namespacedObjects...)
	return objsToCreate, objsToDelete
}

func (c *apiServerComponent) Ready() bool {
	return true
}

// apiServiceRegistration creates an API service that registers Tigera Secure APIs (and API server).
//
// Both Calico and Calico Enterprise, with the same name.
func (c *apiServerComponent) apiServiceRegistration(cert []byte) *apiregv1.APIService {
	// The APIService is the same for OSS and Enterprise, with the exception that
	// it points to a different Service and Namespace for each.
	s := &apiregv1.APIService{
		TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "v3.projectcalico.org",
		},
		Spec: apiregv1.APIServiceSpec{
			Group:                "projectcalico.org",
			VersionPriority:      200,
			GroupPriorityMinimum: 1500,
			Service: &apiregv1.ServiceReference{
				Name:      ProjectCalicoApiServerServiceName(c.cfg.Installation.Variant),
				Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			},
			Version:  "v3",
			CABundle: cert,
		},
	}
	return s
}

// delegateAuthClusterRoleBinding creates a clusterrolebinding that allows the API server to delegate
// authn/authz requests to main API server.
//
// Both Calico and Calico Enterprise, but different names.
func (c *apiServerComponent) delegateAuthClusterRoleBinding() (client.Object, client.Object) {
	// Determine names based on the configured variant.
	var name, nameToDelete string
	enterpriseName := "tigera-apiserver-delegate-auth"
	ossName := "calico-apiserver-delegate-auth"
	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		name = enterpriseName
		nameToDelete = ossName
	case operatorv1.Calico:
		name = ossName
		nameToDelete = enterpriseName
	}

	return &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName(c.cfg.Installation.Variant),
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				Name:     "system:auth-delegator",
				APIGroup: "rbac.authorization.k8s.io",
			},
		}, &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: nameToDelete,
			},
		}

}

// authReaderRoleBinding creates a rolebinding that allows the API server to access the
// extension-apiserver-authentication configmap. That configmap contains the client CA file that
// the main API server was configured with.
//
// Both Calico and Calico Enterprise, but different names.
func (c *apiServerComponent) authReaderRoleBinding() (client.Object, client.Object) {
	var name, nameToDelete string
	enterpriseName := "tigera-auth-reader"
	ossName := "calico-apiserver-auth-reader"
	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		name = enterpriseName
		nameToDelete = ossName
	case operatorv1.Calico:
		name = ossName
		nameToDelete = enterpriseName
	}

	return &rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "kube-system",
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "Role",
				Name:     "extension-apiserver-authentication-reader",
				APIGroup: "rbac.authorization.k8s.io",
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName(c.cfg.Installation.Variant),
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
				},
			},
		}, &rbacv1.RoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "RoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      nameToDelete,
				Namespace: "kube-system",
			},
		}

}

// apiServerServiceAccount creates the service account used by the API server.
//
// Both Calico and Calico Enterprise, but in different namespaces.
func (c *apiServerComponent) apiServerServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName(c.cfg.Installation.Variant),
			Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
		},
	}
}

// calicoCustomResourcesClusterRole creates a clusterrole that gives permissions to access backing CRDs and k8s networkpolicies.
//
// Both Calico and Calico Enterprise, with the same name.
func (c *apiServerComponent) calicoCustomResourcesClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Core Kubernetes resources.
			APIGroups: []string{""},
			Resources: []string{
				"nodes",
				"namespaces",
				"pods",
				"serviceaccounts",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{

			// Kubernetes network policy resources.
			APIGroups: []string{
				"networking.k8s.io",
			},
			Resources: []string{
				"networkpolicies",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		},
		{
			// Core Calico backing storage.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{
				"globalnetworkpolicies",
				"networkpolicies",
				"caliconodestatuses",
				"clusterinformations",
				"hostendpoints",
				"globalnetworksets",
				"networksets",
				"bgpconfigurations",
				"bgppeers",
				"felixconfigurations",
				"kubecontrollersconfigurations",
				"ippools",
				"ipreservations",
				"ipamblocks",
				"blockaffinities",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
				"create",
				"update",
				"delete",
				"patch",
			},
		},
	}
	if !c.cfg.Openshift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"calico-apiserver"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-crds",
		},
		Rules: rules,
	}
}

// calicoCustomResourcesClusterRoleBinding creates a clusterrolebinding that applies calicoCustomResourcesClusterRole to
// the calico-apiserver service account.
//
// Both Calico and Calico Enterprise, with the same name.
func (c *apiServerComponent) calicoCustomResourcesClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-apiserver-access-calico-crds",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName(c.cfg.Installation.Variant),
				Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "calico-crds",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// authClusterRole returns the cluster role to create, and one to delete, based on the variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) authClusterRole() (client.Object, client.Object) {
	var name, nameToDelete string
	enterpriseName := "tigera-extension-apiserver-auth-access"
	ossName := "calico-extension-apiserver-auth-access"
	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		name = enterpriseName
		nameToDelete = ossName
	case operatorv1.Calico:
		name = ossName
		nameToDelete = enterpriseName
	}

	return &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{
						"",
					},
					Resources: []string{
						"configmaps",
					},
					Verbs: []string{
						"list",
						"watch",
					},
					ResourceNames: []string{
						"extension-apiserver-authentication",
					},
				},
				{
					APIGroups: []string{
						"rbac.authorization.k8s.io",
					},
					Resources: []string{
						"clusterroles",
						"clusterrolebindings",
						"roles",
						"rolebindings",
					},
					Verbs: []string{
						"get",
						"list",
						"watch",
					},
				},
			},
		}, &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: nameToDelete,
			},
		}
}

// authClusterRoleBinding returns a clusterrolebinding to create, and a clusterrolebinding to delete.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) authClusterRoleBinding() (client.Object, client.Object) {
	var name, nameToDelete string
	enterpriseName := "tigera-extension-apiserver-auth-access"
	ossName := "calico-extension-apiserver-auth-access"
	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		name = enterpriseName
		nameToDelete = ossName
	case operatorv1.Calico:
		name = ossName
		nameToDelete = enterpriseName
	}

	return &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName(c.cfg.Installation.Variant),
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				Name:     name,
				APIGroup: "rbac.authorization.k8s.io",
			},
		}, &rbacv1.ClusterRoleBinding{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: nameToDelete,
			},
		}

}

// webhookReaderClusterRole returns a ClusterRole to read MutatingWebhookConfigurations and ValidatingWebhookConfigurations and an
// equivalent one to delete based on variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) webhookReaderClusterRole() (client.Object, client.Object) {
	var name, nameToDelete string
	enterpriseName := "tigera-webhook-reader"
	ossName := "calico-webhook-reader"
	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		name = enterpriseName
		nameToDelete = ossName
	case operatorv1.Calico:
		name = ossName
		nameToDelete = enterpriseName
	}

	return &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{
						"admissionregistration.k8s.io",
					},
					Resources: []string{
						"mutatingwebhookconfigurations", "validatingwebhookconfigurations",
					},
					Verbs: []string{
						"get",
						"list",
						"watch",
					},
				},
			},
		}, &rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: nameToDelete,
			},
		}
}

// webhookReaderClusterRoleBinding binds the apiserver ServiceAccount to the webhook-reader. It also returns a version to
// delete, based on variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) webhookReaderClusterRoleBinding() (client.Object, client.Object) {
	var name, nameToDelete, refName string
	enterpriseName := "tigera-apiserver-webhook-reader"
	ossName := "calico-apiserver-webhook-reader"
	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		name = enterpriseName
		nameToDelete = ossName
		refName = "tigera-webhook-reader"
	case operatorv1.Calico:
		name = ossName
		nameToDelete = enterpriseName
		refName = "calico-webhook-reader"
	}

	return &rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName(c.cfg.Installation.Variant),
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
				},
			},
			RoleRef: rbacv1.RoleRef{
				Kind:     "ClusterRole",
				Name:     refName,
				APIGroup: "rbac.authorization.k8s.io",
			},
		}, &rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: nameToDelete},
		}

}

// apiServerService creates a service backed by the API server and - for enterprise - query server.
//
// Both Calico and Calico Enterprise, different namespaces.
func (c *apiServerComponent) apiServerService() *corev1.Service {
	s := &corev1.Service{
		TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      ProjectCalicoApiServerServiceName(c.cfg.Installation.Variant),
			Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       "apiserver",
					Port:       443,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(apiServerPort),
				},
			},
			Selector: map[string]string{
				"apiserver": "true",
			},
		},
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		// Add port for queryserver if enterprise.
		s.Spec.Ports = append(s.Spec.Ports,
			corev1.ServicePort{
				Name:       "queryserver",
				Port:       queryServerPort,
				Protocol:   corev1.ProtocolTCP,
				TargetPort: intstr.FromInt(queryServerPort),
			},
		)

	}
	return s
}

// apiServer creates a deployment containing the API and query servers.
func (c *apiServerComponent) apiServerDeployment() *appsv1.Deployment {
	var name string
	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		name = "tigera-apiserver"
	case operatorv1.Calico:
		name = "calico-apiserver"
	}

	hostNetwork := c.hostNetwork()
	dnsPolicy := corev1.DNSClusterFirst
	if hostNetwork {
		// Adjust DNS policy so we can access in-cluster services.
		dnsPolicy = corev1.DNSClusterFirstWithHostNet
	}

	var initContainers []corev1.Container
	if c.cfg.Installation.CertificateManagement != nil {
		initContainers = append(initContainers, CreateCSRInitContainer(
			c.cfg.Installation.CertificateManagement,
			c.certSignReqImage,
			ProjectCalicoApiServerTLSSecretName(c.cfg.Installation.Variant), TLSSecretCertName,
			APIServerSecretKeyName,
			APIServerSecretCertName,
			dns.GetServiceDNSNames(ProjectCalicoApiServerServiceName(c.cfg.Installation.Variant), rmeta.APIServerNamespace(c.cfg.Installation.Variant), c.cfg.ClusterDomain),
			rmeta.APIServerNamespace(c.cfg.Installation.Variant)))
	}

	d := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			Labels: map[string]string{
				"apiserver": "true",
				"k8s-app":   name,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: c.cfg.Installation.ControlPlaneReplicas,
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"apiserver": "true"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
					Labels: map[string]string{
						"apiserver": "true",
						"k8s-app":   name,
					},
					Annotations: c.tlsAnnotations,
				},
				Spec: corev1.PodSpec{
					DNSPolicy:          dnsPolicy,
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					HostNetwork:        hostNetwork,
					ServiceAccountName: serviceAccountName(c.cfg.Installation.Variant),
					Tolerations:        c.tolerations(),
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					InitContainers:     initContainers,
					Containers: []corev1.Container{
						c.apiServerContainer(),
					},
					Volumes: c.apiServerVolumes(),
				},
			},
		},
	}

	if c.cfg.Installation.ControlPlaneReplicas != nil && *c.cfg.Installation.ControlPlaneReplicas > 1 {
		d.Spec.Template.Spec.Affinity = podaffinity.NewPodAntiAffinity(name, rmeta.APIServerNamespace(c.cfg.Installation.Variant))
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		d.Spec.Template.Spec.Containers = append(d.Spec.Template.Spec.Containers, c.queryServerContainer())
	}

	return d
}

func (c *apiServerComponent) hostNetwork() bool {
	hostNetwork := c.cfg.ForceHostNetwork
	if c.cfg.Installation.KubernetesProvider == operatorv1.ProviderEKS &&
		c.cfg.Installation.CNI.Type == operatorv1.PluginCalico {
		// Workaround the fact that webhooks don't work for non-host-networked pods
		// when in this networking mode on EKS, because the control plane nodes don't run
		// Calico.
		hostNetwork = true
	}
	return hostNetwork
}

// apiServerContainer creates the API server container.
func (c *apiServerComponent) apiServerContainer() corev1.Container {
	volumeMounts := []corev1.VolumeMount{}
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{Name: "tigera-audit-logs", MountPath: "/var/log/calico/audit"},
			corev1.VolumeMount{Name: "tigera-audit-policy", MountPath: "/etc/tigera/audit"},
		)
	}

	volumeMounts = append(volumeMounts,
		corev1.VolumeMount{Name: ProjectCalicoApiServerTLSSecretName(c.cfg.Installation.Variant), MountPath: "/code/apiserver.local.config/certificates"},
	)

	if c.cfg.ManagementCluster != nil {
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{
				Name:      VoltronTunnelSecretName,
				MountPath: "/code/apiserver.local.config/multicluster/certificates",
				ReadOnly:  true,
			},
		)
	}

	// On OpenShift apiserver needs privileged access to write audit logs to host path volume
	isPrivileged := false
	if c.cfg.Openshift {
		isPrivileged = true
	}

	env := []corev1.EnvVar{
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
	}

	env = append(env, c.cfg.K8SServiceEndpoint.EnvVars(c.hostNetwork(), c.cfg.Installation.KubernetesProvider)...)

	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	var name string
	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		name = "tigera-apiserver"
	case operatorv1.Calico:
		name = "calico-apiserver"
	}

	apiServer := corev1.Container{
		Name:  name,
		Image: c.apiServerImage,
		Args:  c.startUpArgs(),
		Env:   env,
		// Needed for permissions to write to the audit log
		SecurityContext: &corev1.SecurityContext{
			Privileged: &isPrivileged,
			RunAsUser:  ptr.Int64ToPtr(0),
		},
		VolumeMounts: volumeMounts,
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt(apiServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
			PeriodSeconds:       10,
		},
		ReadinessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				Exec: &corev1.ExecAction{
					Command: []string{
						"/code/filecheck",
					},
				},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       10,
			FailureThreshold:    5,
		},
	}

	return apiServer
}

func (c *apiServerComponent) startUpArgs() []string {
	args := []string{
		fmt.Sprintf("--secure-port=%d", apiServerPort),
	}

	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		args = append(args,
			"--audit-policy-file=/etc/tigera/audit/policy.conf",
			"--audit-log-path=/var/log/calico/audit/tsee-audit.log",
		)
	}

	if c.cfg.ManagementCluster != nil {
		args = append(args, "--enable-managed-clusters-create-api=true")
		if c.cfg.ManagementCluster.Spec.Address != "" {
			args = append(args, fmt.Sprintf("--managementClusterAddr=%s", c.cfg.ManagementCluster.Spec.Address))
		}
	}

	return args
}

// queryServerContainer creates the query server container.
func (c *apiServerComponent) queryServerContainer() corev1.Container {
	env := []corev1.EnvVar{
		// Set queryserver logging to "info"
		{Name: "LOGLEVEL", Value: "info"},
		{Name: "DATASTORE_TYPE", Value: "kubernetes"},
	}

	env = append(env, c.cfg.K8SServiceEndpoint.EnvVars(c.hostNetwork(), c.cfg.Installation.KubernetesProvider)...)
	env = append(env, GetTigeraSecurityGroupEnvVariables(c.cfg.AmazonCloudIntegration)...)

	if c.cfg.Installation.CalicoNetwork != nil && c.cfg.Installation.CalicoNetwork.MultiInterfaceMode != nil {
		env = append(env, corev1.EnvVar{Name: "MULTI_INTERFACE_MODE", Value: c.cfg.Installation.CalicoNetwork.MultiInterfaceMode.Value()})
	}

	container := corev1.Container{
		Name:  "tigera-queryserver",
		Image: c.queryServerImage,
		Env:   env,
		LivenessProbe: &corev1.Probe{
			Handler: corev1.Handler{
				HTTPGet: &corev1.HTTPGetAction{
					Path:   "/version",
					Port:   intstr.FromInt(queryServerPort),
					Scheme: corev1.URISchemeHTTPS,
				},
			},
			InitialDelaySeconds: 90,
			PeriodSeconds:       10,
		},
		SecurityContext: podsecuritycontext.NewBaseContext(),
	}
	return container
}

// apiServerVolumes creates the volumes used by the API server deployment.
func (c *apiServerComponent) apiServerVolumes() []corev1.Volume {
	volumes := []corev1.Volume{}
	hostPathType := corev1.HostPathDirectoryOrCreate
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		volumes = append(volumes,
			corev1.Volume{
				Name: "tigera-audit-logs",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/var/log/calico/audit",
						Type: &hostPathType,
					},
				},
			},
			corev1.Volume{
				Name: "tigera-audit-policy",
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "tigera-audit-policy"},
						Items: []corev1.KeyToPath{
							{
								Key:  "config",
								Path: "policy.conf",
							},
						},
					},
				},
			},
		)

		if c.cfg.ManagementCluster != nil {
			volumes = append(volumes, corev1.Volume{
				// Append volume for tunnel CA certificate
				Name: VoltronTunnelSecretName,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName: VoltronTunnelSecretName,
					},
				},
			})
		}
	}

	volumes = append(volumes,
		corev1.Volume{
			Name:         ProjectCalicoApiServerTLSSecretName(c.cfg.Installation.Variant),
			VolumeSource: certificateVolumeSource(c.cfg.Installation.CertificateManagement, ProjectCalicoApiServerTLSSecretName(c.cfg.Installation.Variant)),
		},
	)

	return volumes
}

// tolerations creates the tolerations used by the API server deployment.
func (c *apiServerComponent) tolerations() []corev1.Toleration {
	if c.hostNetwork() {
		return rmeta.TolerateAll
	}
	return append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateMaster)
}

func (c *apiServerComponent) getTLSObjects() []client.Object {
	objs := []client.Object{}
	for _, s := range c.tlsSecrets {
		objs = append(objs, s)
	}

	return objs
}

// apiServerPodSecurityPolicy returns a PSP to create and a PSP to delete based on variant.
//
// Both Calico and Calico Enterprise, with different names.
func (c *apiServerComponent) apiServerPodSecurityPolicy() (client.Object, client.Object) {
	var name, nameToDelete string
	enterpriseName := "tigera-apiserver"
	ossName := "calico-apiserver"

	switch c.cfg.Installation.Variant {
	case operatorv1.TigeraSecureEnterprise:
		name = enterpriseName
		nameToDelete = ossName
	case operatorv1.Calico:
		name = ossName
		nameToDelete = enterpriseName
	}

	psp := podsecuritypolicy.NewBasePolicy()
	psp.GetObjectMeta().SetName(name)
	psp.Spec.Privileged = false
	psp.Spec.AllowPrivilegeEscalation = ptr.BoolToPtr(false)
	psp.Spec.Volumes = append(psp.Spec.Volumes, policyv1beta1.HostPath)
	psp.Spec.RunAsUser.Rule = policyv1beta1.RunAsUserStrategyRunAsAny

	pspToDelete := podsecuritypolicy.NewBasePolicy()
	pspToDelete.GetObjectMeta().SetName(nameToDelete)

	return psp, pspToDelete
}

// networkPolicy returns a NP to allow traffic to the API server. This prevents it from
// being cut off from the main API server. The enterprise equivalent is currently handled in manifests.
//
// Calico only.
func (c *apiServerComponent) networkPolicy() *netv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	p := intstr.FromInt(5443)
	return &netv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "allow-apiserver", Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant)},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"apiserver": "true",
				},
			},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
			Ingress: []netv1.NetworkPolicyIngressRule{
				{
					Ports: []netv1.NetworkPolicyPort{
						{
							Protocol: &tcp,
							Port:     &p,
						},
					},
				},
			},
		},
	}
}

// tigeraCustomResourcesClusterRole creates a clusterrole that gives permissions to access backing CRDs
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraCustomResourcesClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			// Calico Enterprise backing storage.
			APIGroups: []string{"crd.projectcalico.org"},
			Resources: []string{
				"stagedkubernetesnetworkpolicies",
				"stagednetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tiers",
				"licensekeys",
				"globalalerts",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
				"globalreporttypes",
				"globalreports",
				"remoteclusterconfigurations",
				"managedclusters",
				"packetcaptures",
				"deeppacketinspections",
				"deeppacketinspections/status",
				"uisettingsgroups",
				"uisettings",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
				"create",
				"update",
				"delete",
				"patch",
			},
		},
	}
	if !c.cfg.Openshift {
		// Allow access to the pod security policy in case this is enforced on the cluster
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{"policy"},
			Resources:     []string{"podsecuritypolicies"},
			Verbs:         []string{"use"},
			ResourceNames: []string{"tigera-apiserver"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-crds",
		},
		Rules: rules,
	}
}

// tigeraCustomResourcesClusterRoleBinding creates a clusterrolebinding that applies tigeraCustomResourcesClusterRole to
// the tigera-apiserver service account.
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraCustomResourcesClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-apiserver-access-tigera-crds",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName(c.cfg.Installation.Variant),
				Namespace: rmeta.APIServerNamespace(c.cfg.Installation.Variant),
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-crds",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// tierGetterClusterRole creates a clusterrole that gives permissions to get tiers.
//
// Calico Enterprise only
func (c *apiServerComponent) tierGetterClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tier-getter",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"tiers",
				},
				Verbs: []string{"get"},
			},
		},
	}
}

// kubeControllerMgrTierGetterClusterRoleBinding creates a rolebinding that allows the k8s kube-controller manager to
// get tiers. In k8s 1.15+, cascading resource deletions (for instance pods for a replicaset) failed
// due to k8s kube-controller not having permissions to get tiers.
//
// Calico Enterprise only
func (c *apiServerComponent) kubeControllerMgrTierGetterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tier-getter",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-tier-getter",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     "system:kube-controller-manager",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}
}

// uisettingsgroupGetterClusterRole creates a clusterrole that gives permissions to get uisettingsgroups.
//
// Calico Enterprise only
func (c *apiServerComponent) uisettingsgroupGetterClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-uisettingsgroup-getter",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{
					"uisettingsgroups",
				},
				Verbs: []string{"get"},
			},
		},
	}
}

// kubeControllerMgrUisettingsgroupGetterClusterRoleBinding creates a rolebinding that allows the k8s kube-controller
// manager to get uisettingsgroups.
//
// In k8s 1.15+, cascading resource deletions (for instance pods for a replicaset) failed due to k8s kube-controller
// not having permissions to get tiers. UISettings and UISettingsGroups RBAC works in a similar way to tiered policy
// and so we need similar RBAC for UISettingsGroups.
//
// Calico Enterprise only
func (c *apiServerComponent) kubeControllerMgrUisettingsgroupGetterClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-uisettingsgroup-getter",
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-uisettingsgroup-getter",
			APIGroup: "rbac.authorization.k8s.io",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "User",
				Name:     "system:kube-controller-manager",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
	}
}

// tigeraUserClusterRole returns a cluster role for a default Calico Enterprise user.
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraUserClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// List requests that the Tigera manager needs.
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
				"",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "tigera-tiered-policy-passthrough" for
			// more details).  Similar for all tiered policy resource types.
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"namespaces",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"uisettingsgroup/data",
			},
			Verbs: []string{"watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures"},
			Verbs:     []string{"get", "list", "watch"},
		},
		// Additional "list" requests required to view flows.
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
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
		// Access to policies in all tiers
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"tiers"},
			Verbs:     []string{"get"},
		},
		// List and download the reports in the Tigera Secure manager.
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
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		// List and view the threat defense configuration
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
			},
			Verbs: []string{"get", "watch", "list"},
		},
		// A POST to AuthorizationReviews lets the UI determine what features it can enable.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authorizationreviews"},
			Verbs:     []string{"create"},
		},
	}

	// Privileges for lma.tigera.io have no effect on managed clusters.
	if c.cfg.ManagementClusterConnection == nil {
		// Access to flow logs, audit logs, and statistics.
		// Access to log into Kibana for oidc users.
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "kibana_login",
			},
			Verbs: []string{"get"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-ui-user",
		},
		Rules: rules,
	}
}

// tigeraNetworkAdminClusterRole returns a cluster role for a Tigera Secure manager network admin.
//
// Calico Enterprise only
func (c *apiServerComponent) tigeraNetworkAdminClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		// Full access to all network policies
		{
			APIGroups: []string{
				"projectcalico.org",
				"networking.k8s.io",
				"extensions",
			},
			// Use both the networkpolicies and tier.networkpolicies resource types to ensure identical behavior
			// irrespective of the Calico RBAC scheme (see the ClusterRole "tigera-tiered-policy-passthrough" for
			// more details).  Similar for all tiered policy resource types.
			Resources: []string{
				"tiers",
				"networkpolicies",
				"tier.networkpolicies",
				"globalnetworkpolicies",
				"tier.globalnetworkpolicies",
				"stagedglobalnetworkpolicies",
				"tier.stagedglobalnetworkpolicies",
				"stagednetworkpolicies",
				"tier.stagednetworkpolicies",
				"stagedkubernetesnetworkpolicies",
				"globalnetworksets",
				"networksets",
				"managedclusters",
				"packetcaptures",
				"uisettingsgroup/data",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"packetcaptures/files"},
			Verbs:     []string{"get", "delete"},
		},
		// Additional "list" requests that the Tigera Secure manager needs
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"watch", "list"},
		},
		// Additional "list" requests required to view flows.
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"list"},
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
		// Manage globalreport configuration, view report generation status, and list reports in the Tigera Secure manager.
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
		// List and download the reports in the Tigera Secure manager.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"globalreporttypes"},
			Verbs:     []string{"get"},
		},
		// Access to cluster information containing Calico and EE versions from the UI.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"clusterinformations"},
			Verbs:     []string{"get", "list"},
		},
		// Manage the threat defense configuration
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{
				"globalalerts",
				"globalalerts/status",
				"globalalerttemplates",
				"globalthreatfeeds",
				"globalthreatfeeds/status",
			},
			Verbs: []string{"create", "update", "delete", "patch", "get", "watch", "list"},
		},
		// A POST to AuthorizationReviews lets the UI determine what features it can enable.
		{
			APIGroups: []string{"projectcalico.org"},
			Resources: []string{"authorizationreviews"},
			Verbs:     []string{"create"},
		},
	}

	// Privileges for lma.tigera.io have no effect on managed clusters.
	if c.cfg.ManagementClusterConnection == nil {
		// Access to flow logs, audit logs, and statistics.
		// Elasticsearch superuser access once logged into Kibana.
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{"lma.tigera.io"},
			Resources: []string{"*"},
			ResourceNames: []string{
				"flows", "audit*", "l7", "events", "dns", "elasticsearch_superuser",
			},
			Verbs: []string{"get"},
		})
	}

	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-network-admin",
		},
		Rules: rules,
	}
}

// tieredPolicyPassthruClusterRole creates a clusterrole that is used to control the RBAC
// mechanism for Tigera Secure tiered policy.
//
// Calico Enterprise only
func (c *apiServerComponent) tieredPolicyPassthruClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tiered-policy-passthrough",
		},
		// If tiered policy is enabled we allow all authenticated users to access the main tier resource, instead
		// restricting access using the tier.xxx resource type. Kubernetes NetworkPolicy and the
		// StagedKubernetesNetworkPolicy are handled using normal (non-tiered) RBAC.
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"networkpolicies", "globalnetworkpolicies", "stagednetworkpolicies", "stagedglobalnetworkpolicies"},
				Verbs:     []string{"*"},
			},
		},
	}
}

// tieredPolicyPassthruClusterRolebinding creates a clusterrolebinding that applies tieredPolicyPassthruClusterRole to all users.
//
// Calico Enterprise only
func (c *apiServerComponent) tieredPolicyPassthruClusterRolebinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-tiered-policy-passthrough",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-tiered-policy-passthrough",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// uiSettingsPassthruClusterRole creates a clusterrole that is used to control the RBAC mechanism for Tigera UI Settings.
// RBAC for these is handled within the Tigera API Server which checks uisettingsgroups/data permissions for the user.
//
// Calico Enterprise only
func (c *apiServerComponent) uiSettingsPassthruClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-uisettings-passthrough",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"uisettings"},
				Verbs:     []string{"*"},
			},
		},
	}
}

// uiSettingsPassthruClusterRolebinding creates a clusterrolebinding that applies uiSettingsPassthruClusterRole to all
// users.
//
// Calico Enterprise only.
func (c *apiServerComponent) uiSettingsPassthruClusterRolebinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tigera-uisettings-passthrough",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "tigera-uisettings-passthrough",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

// auditPolicyConfigMap returns a configmap with contents to configure audit logging for
// projectcalico.org/v3 APIs.
//
// Calico Enterprise only
func (c *apiServerComponent) auditPolicyConfigMap() *corev1.ConfigMap {
	const defaultAuditPolicy = `apiVersion: audit.k8s.io/v1beta1
kind: Policy
rules:
- level: RequestResponse
  omitStages:
  - RequestReceived
  verbs:
  - create
  - patch
  - update
  - delete
  resources:
  - group: projectcalico.org
    resources:
    - globalnetworkpolicies
    - networkpolicies
    - stagedglobalnetworkpolicies
    - stagednetworkpolicies
    - stagedkubernetesnetworkpolicies
    - globalnetworksets
    - networksets
    - tiers
    - hostendpoints`

	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			// This object is for Enterprise only, so pass it explicitly.
			Namespace: rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise),
			Name:      "tigera-audit-policy",
		},
		Data: map[string]string{
			"config": defaultAuditPolicy,
		},
	}
}
