package utils

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/render/common/cloudrbac"
	rcimageassurance "github.com/tigera/operator/pkg/render/common/imageassurance"
	iarender "github.com/tigera/operator/pkg/render/imageassurance"
)

// AddImageAssuranceWatch adds watches for Image Assurance.
func AddImageAssuranceWatch(c controller.Controller, destNamespace string) error {
	// Watch the given secrets in each both the operator namespace and the destNamespace for cloud
	for _, namespace := range []string{common.OperatorNamespace(), destNamespace} {
		for _, secretName := range []string{iarender.APICertSecretName} {
			if err := AddSecretsWatch(c, secretName, namespace); err != nil {
				return fmt.Errorf("failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	// Watch for changes to primary resource ImageAssurance
	if err := c.Watch(&source.Kind{Type: &operatorv1.ImageAssurance{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("failed to watch Image Assurance resource: %w", err)
	}

	return nil
}

// GetImageAssurance returns the default ImageAssurance instance.
func GetImageAssurance(ctx context.Context, cli client.Client) (*operatorv1.ImageAssurance, error) {
	instance := &operatorv1.ImageAssurance{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

// GetImageAssuranceTLSSecret gets the TLS secret for Image Assurance API communication.
func GetImageAssuranceTLSSecret(client client.Client) (*corev1.Secret, error) {
	return ValidateCertPair(client, common.OperatorNamespace(), iarender.APICertSecretName, "", corev1.TLSCertKey)
}

// GetImageAssuranceConfigurationConfigMap gets the Image Assurance configuration configmap.
func GetImageAssuranceConfigurationConfigMap(client client.Client) (*corev1.ConfigMap, error) {
	cm := &corev1.ConfigMap{}
	nn := types.NamespacedName{
		Name:      rcimageassurance.ConfigurationConfigMapName,
		Namespace: common.OperatorNamespace(),
	}

	if err := client.Get(context.Background(), nn, cm); err != nil {
		return nil, fmt.Errorf("failed to read secret %q: %s", rcimageassurance.ConfigurationConfigMapName, err)
	}

	if orgID, ok := cm.Data[rcimageassurance.ConfigurationConfigMapOrgIDKey]; !ok || len(orgID) == 0 {
		return nil, fmt.Errorf("expected configmap %q to have a field named %q",
			rcimageassurance.ConfigurationConfigMapName, rcimageassurance.ConfigurationConfigMapOrgIDKey)
	}

	return cm, nil
}

func AddServiceAccountWatch(c controller.Controller, name string, namespace string) error {
	serviceAccount := &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	return AddNamespacedWatch(c, serviceAccount)
}

func AddClusterRoleBindingWatch(c controller.Controller, name string) error {
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	return AddClusterResourceWatch(c, crb)
}

// GetCloudRBAC returns the default CloudRBAC instance.
func GetCloudRBAC(ctx context.Context, cli client.Client) (*operatorv1.CloudRBAC, error) {
	instance := &operatorv1.CloudRBAC{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

// GetCloudRbacTLSSecret gets the TLS secret for the Cloud RBAC API communication.
func GetCloudRbacTLSSecret(client client.Client) (*corev1.Secret, error) {
	return ValidateCertPair(client, common.OperatorNamespace(), cloudrbac.TLSSecretName, corev1.TLSPrivateKeyKey, corev1.TLSCertKey)
}

func AddCloudRBACWatch(c controller.Controller, destNamespace string) error {

	// Watch the given tls secrets in each both the operator namespace and the destNamespace for cloud
	for _, namespace := range []string{common.OperatorNamespace(), destNamespace} {
		secretName := cloudrbac.TLSSecretName
		if err := AddSecretsWatch(c, secretName, namespace); err != nil {
			return fmt.Errorf("failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
		}
	}

	return nil
}

// GetImageAssuranceAPIAccessToken returns the image assurance service account secret token created by kube-controllers.
// It takes in service account name and uses it to validate the existence of the service account and return the token if present.
func GetImageAssuranceAPIAccessToken(c client.Client, resourceName string) ([]byte, error) {
	// Ensure that the service account is present.
	sa := &corev1.ServiceAccount{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name:      resourceName,
		Namespace: common.OperatorNamespace(),
	}, sa); err != nil {
		return nil, err
	}

	// Ensure that there is a secret present against the service account with the same resource name.
	// This secret is created by kube-controllers along with the creation of service account, this secret is created
	// explicitly using authv1.TokenRequest (previously they were created automatically for k8s versions below v1.24)
	saSecret := &corev1.Secret{}
	err := c.Get(context.Background(), types.NamespacedName{
		Name:      resourceName,
		Namespace: common.OperatorNamespace()},
		saSecret)

	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return saSecret.Data["token"], nil
}
