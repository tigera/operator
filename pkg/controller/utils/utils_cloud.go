package utils

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
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
