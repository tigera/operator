// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	// If this annotation is set on an object, the operator will ignore it, allowing user modifications.
	// This is for development and testing purposes only. Do not use this annotation
	// for production, as this will cause problems with upgrade.
	unsupportedIgnoreAnnotation = "unsupported.operator.tigera.io/ignore"
)

var DefaultInstanceKey = client.ObjectKey{Name: "default"}
var OverridesInstanceKey = client.ObjectKey{Name: "overrides"}
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

func AddNamespaceWatch(c controller.Controller, name string) error {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	return c.Watch(&source.Kind{Type: ns}, &handler.EnqueueRequestForObject{})
}

type MetaMatch func(metav1.ObjectMeta) bool

func AddSecretsWatch(c controller.Controller, name, namespace string, metaMatches ...MetaMatch) error {
	s := &v1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	return addNamespacedWatch(c, s, metaMatches...)
}

func AddConfigMapWatch(c controller.Controller, name, namespace string) error {
	cm := &v1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	return addNamespacedWatch(c, cm)
}

func AddServiceWatch(c controller.Controller, name, namespace string) error {
	return addNamespacedWatch(c, &v1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	})
}

// addWatch creates a watch on the given object. If a name and namespace are provided, then it will
// use predicates to only return matching objects. If they are not, then all events of the provided kind
// will be generated.
func addNamespacedWatch(c controller.Controller, obj runtime.Object, metaMatches ...MetaMatch) error {
	objMeta := obj.(metav1.ObjectMetaAccessor).GetObjectMeta()
	if objMeta.GetNamespace() == "" {
		return fmt.Errorf("No namespace provided for namespaced watch")
	}
	pred := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			if objMeta.GetName() != "" && e.Meta.GetName() != objMeta.GetName() {
				return false
			}
			return e.Meta.GetNamespace() == objMeta.GetNamespace()
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if objMeta.GetName() != "" && e.MetaNew.GetName() != objMeta.GetName() {
				return false
			}
			return e.MetaNew.GetNamespace() == objMeta.GetNamespace()
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			if objMeta.GetName() != "" && e.Meta.GetName() != objMeta.GetName() {
				return false
			}
			return e.Meta.GetNamespace() == objMeta.GetNamespace()
		},
	}
	return c.Watch(&source.Kind{Type: obj}, &handler.EnqueueRequestForObject{}, pred)
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

	if instance.Status.State != operatorv1.TigeraStatusReady {
		l.V(3).Info("APIServer resource not ready")
		return false
	}
	return true
}

func LogStorageExists(ctx context.Context, cli client.Client) (bool, error) {
	instance := &operatorv1.LogStorage{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, instance)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// CheckLicenseKey checks if a license has been installed. It's useful
// to prevent rollout of TSEE components that might require it.
// It will return an error if the license is not installed, and nil otherwise.
func CheckLicenseKey(ctx context.Context, cli client.Client) error {
	instance := &v3.LicenseKey{}
	return cli.Get(ctx, DefaultInstanceKey, instance)
}

// ValidateCertPair checks if the given secret exists and if so
// that it contains key and cert fields. If a secret exists then it is returned.
// If there is an error accessing the secret (except NotFound) or the cert
// does not have both a key and cert field then an appropriate error is returned.
// If no secret exists then nil, nil is returned to represent that no cert is valid.
func ValidateCertPair(client client.Client, certPairSecretName, keyName, certName string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      certPairSecretName,
		Namespace: render.OperatorNamespace(),
	}
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
	for _, ps := range i.Status.Computed.ImagePullSecrets {
		s := &corev1.Secret{}
		err := c.Get(context.Background(), client.ObjectKey{Name: ps.Name, Namespace: render.OperatorNamespace()}, s)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}

	return secrets, nil
}

// Return the ManagementCluster CR if present. No error is returned if it was not found.
func GetManagementCluster(ctx context.Context, c client.Client) (*operatorv1.ManagementCluster, error) {
	managementCluster := &operatorv1.ManagementCluster{}

	err := c.Get(ctx, DefaultTSEEInstanceKey, managementCluster)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return managementCluster, nil
}

// Return the ManagementClusterConnection CR if present. No error is returned if it was not found.
func GetManagementClusterConnection(ctx context.Context, c client.Client) (*operatorv1.ManagementClusterConnection, error) {
	managementClusterConnection := &operatorv1.ManagementClusterConnection{}

	err := c.Get(ctx, DefaultTSEEInstanceKey, managementClusterConnection)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return managementClusterConnection, nil
}

// GetAmazonCloudIntegration returns the tigera AmazonCloudIntegration instance.
func GetAmazonCloudIntegration(ctx context.Context, client client.Client) (*operatorv1.AmazonCloudIntegration, error) {
	// Fetch the Installation instance. We only support a single instance named "tsee-secure".
	instance := &operatorv1.AmazonCloudIntegration{}
	err := client.Get(ctx, DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

// GetAuthentication finds the authentication CR in your cluster.
func GetAuthentication(ctx context.Context, cli client.Client) (*operatorv1.Authentication, error) {
	authentication := &operatorv1.Authentication{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, authentication)
	if err != nil {
		return nil, err
	}

	return authentication, nil
}
