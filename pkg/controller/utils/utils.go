package utils

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	// If this annotation is set on an object, the operator will ignore it, allowing user modifications.
	// This is for development and testing purposes only. Do not use this annotation
	// for production, as this will cause problems with upgrade.
	unsupportedIgnoreAnnotation = "unsupported.operator.tigera.io/ignore"
)

var DefaultInstanceKey = client.ObjectKey{Name: "default"}
var DefaultTSEEInstanceKey = client.ObjectKey{Name: "tigera-secure"}

// ContextLoggerForResource provides a logger instance with context set for the provided object.
func ContextLoggerForResource(log logr.Logger, obj runtime.Object) logr.Logger {
	gvk := obj.GetObjectKind().GroupVersionKind()
	name := obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
	namespace := obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()
	return log.WithValues("Name", name, "Namespace", namespace, "Kind", gvk.Kind)
}

// IgnoreObject returns true if the object has been marked as ignored by the user,
// and returns false otherwise.
func IgnoreObject(obj runtime.Object) bool {
	a := obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetAnnotations()
	if val, ok := a[unsupportedIgnoreAnnotation]; ok && val == "true" {
		return true
	}
	return false
}

func AddNetworkWatch(c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operatorv1.Installation{}}, &handler.EnqueueRequestForObject{})
}

func AddAPIServerWatch(c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operatorv1.APIServer{}}, &handler.EnqueueRequestForObject{})
}

func AddComplianceWatch(c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operatorv1.Compliance{}}, &handler.EnqueueRequestForObject{})
}

func IsAPIServerReady(client client.Client, l logr.Logger) bool {
	instance := &operatorv1.APIServer{}
	err := client.Get(context.Background(), DefaultTSEEInstanceKey, instance)
	if err != nil {
		if kerrors.IsNotFound(err) {
			l.V(3).Info("APIServer resource does not exist")
			return false
		}
		l.Error(err, "Unable to retrieve APIServer resource")
		return false
	}

	if instance.Status.State != operatorv1.APIServerStatusReady {
		l.V(3).Info("APIServer resource not ready")
		return false
	}
	return true
}

// CheckLicenseKey checks if a license has been installed. It's useful
// to prevent rollout of TSEE components that might require it.
// It will return an error if the license is not installed, and nil otherwise.
func CheckLicenseKey(ctx context.Context, cli client.Client) error {
	instance := &v3.LicenseKey{}
	return cli.Get(ctx, DefaultInstanceKey, instance)
}

// validateCertPair checks if the given secret exists and if so
// that it contains key and cert fields. If a secret exists then it is returned.
// If there is an error accessing the secret (except NotFound) or the cert
// does not have both a key and cert field then an appropriate error is returned.
// If no secret exists then nil, nil is returned to represent that no cert is valid.
func ValidateCertPair(client client.Client, certPairSecretName, keyName, certName, ns string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{Name: certPairSecretName, Namespace: ns}
	err := client.Get(context.Background(), secretNamespacedName, secret)
	if err != nil {
		// If the reason for the error is not found then that is acceptable
		// so return valid in that case.
		statErr, ok := err.(*kerrors.StatusError)
		if ok && statErr.ErrStatus.Reason == metav1.StatusReasonNotFound {
			return nil, nil
		} else {
			return nil, fmt.Errorf("Failed to read cert %q from datastore: %s", certPairSecretName, err)
		}
	}

	if val, ok := secret.Data[keyName]; !ok || len(val) == 0 {
		return secret, fmt.Errorf("Secret %q does not have a field named %q", certPairSecretName, keyName)
	}
	if val, ok := secret.Data[certName]; !ok || len(val) == 0 {
		return secret, fmt.Errorf("Secret %q does not have a field named %q", certPairSecretName, certName)
	}

	return secret, nil
}

func GetNetworkingPullSecrets(i *operatorv1.Installation, c client.Client) ([]*corev1.Secret, error) {
	secrets := []*corev1.Secret{}
	for _, ps := range i.Spec.ImagePullSecrets {
		s := &corev1.Secret{}
		err := c.Get(context.Background(), client.ObjectKey{Name: ps.Name, Namespace: "tigera-operator"}, s)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}

	return secrets, nil
}
