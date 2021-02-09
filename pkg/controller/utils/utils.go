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

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
)

const (
	// If this annotation is set on an object, the operator will ignore it, allowing user modifications.
	// This is for development and testing purposes only. Do not use this annotation
	// for production, as this will cause problems with upgrade.
	unsupportedIgnoreAnnotation = "unsupported.operator.tigera.io/ignore"
)

var DefaultInstanceKey = client.ObjectKey{Name: "default"}
var DefaultTSEEInstanceKey = client.ObjectKey{Name: "tigera-secure"}
var OverlayInstanceKey = client.ObjectKey{Name: "overlay"}

// ContextLoggerForResource provides a logger instance with context set for the provided object.
func ContextLoggerForResource(log logr.Logger, obj client.Object) logr.Logger {
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
func addNamespacedWatch(c controller.Controller, obj client.Object, metaMatches ...MetaMatch) error {
	objMeta := obj.(metav1.ObjectMetaAccessor).GetObjectMeta()
	if objMeta.GetNamespace() == "" {
		return fmt.Errorf("No namespace provided for namespaced watch")
	}
	pred := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			if objMeta.GetName() != "" && e.Object.GetName() != objMeta.GetName() {
				return false
			}
			return e.Object.GetNamespace() == objMeta.GetNamespace()
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if objMeta.GetName() != "" && e.ObjectNew.GetName() != objMeta.GetName() {
				return false
			}
			return e.ObjectNew.GetNamespace() == objMeta.GetNamespace()
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			if objMeta.GetName() != "" && e.Object.GetName() != objMeta.GetName() {
				return false
			}
			return e.Object.GetNamespace() == objMeta.GetNamespace()
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

// FetchLicenseKey returns the license if it has been installed. It's useful
// to prevent rollout of TSEE components that might require it.
// It will return an error if the license is not installed.
func FetchLicenseKey(ctx context.Context, cli client.Client) (v3.LicenseKey, error) {
	instance := &v3.LicenseKey{}
	err := cli.Get(ctx, DefaultInstanceKey, instance)
	return *instance, err
}

// IsFeatureActive return true if the feature is listed in LicenseStatusKey
func IsFeatureActive(license v3.LicenseKey, featureName string) bool {
	for _, v := range license.Status.Features {
		if v == featureName {
			return true
		}
	}

	return false
}

// ValidateCertPair validates the cert pair secret in the tigera-operator namespace.
func ValidateCertPair(client client.Client, certPairSecretName, keyName, certName string) (*corev1.Secret, error) {
	return ValidateCertPairInNamespace(client, render.OperatorNamespace(), certPairSecretName, keyName, certName)
}

// ValidateCertPairInNamespace checks if the given secret exists in the given
// namespace and if so that it contains key and cert fields. If a secret exists then it is returned.
// If there is an error accessing the secret (except NotFound) or the cert
// does not have both a key and cert field then an appropriate error is returned.
// If no secret exists then nil, nil is returned to represent that no cert is valid.
// TODO: Replace this with version of ValidateCertPair taking in a ns.
func ValidateCertPairInNamespace(client client.Client, namespace, certPairSecretName, keyName, certName string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      certPairSecretName,
		Namespace: namespace,
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

func GetNetworkingPullSecrets(i *operatorv1.InstallationSpec, c client.Client) ([]*corev1.Secret, error) {
	secrets := []*corev1.Secret{}
	for _, ps := range i.ImagePullSecrets {
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

// GetTyphaScaleCount will return the number of Typhas needed for the number of nodes.
func GetExpectedTyphaScale(nodes int) int {
	var maxNodesPerTypha int = 200
	// This gives a count of how many 200s so we need 1+ this number to get at least
	// 1 typha for every 200 nodes.
	typhas := (nodes / maxNodesPerTypha) + 1
	// We add one more to ensure there is always 1 extra for high availability purposes.
	typhas += 1
	// If we don't have enough nodes to have 3 typhs then make sure there is one typha for each node.
	if nodes <= 3 {
		typhas = nodes
	} else if typhas < 3 { // If typhas is less than 3 always make sure we have 3
		typhas = 3
	}
	return typhas
}

// GetElasticLicenseType returns the license type from elastic-licensing ConfigMap that ECK operator keeps updated.
func GetElasticLicenseType(ctx context.Context, cli client.Client, logger logr.Logger) (render.ElasticsearchLicenseType, error) {
	cm := &corev1.ConfigMap{}
	err := cli.Get(ctx, client.ObjectKey{Name: render.ECKLicenseConfigMapName, Namespace: render.ECKOperatorNamespace}, cm)
	if err != nil {
		return render.ElasticsearchLicenseTypeUnknown, err
	}
	license, ok := cm.Data["eck_license_level"]
	if !ok {
		return render.ElasticsearchLicenseTypeUnknown, fmt.Errorf("eck_license_level not available.")
	}

	return StrToElasticLicenseType(license, logger), nil
}

// StrToElasticLicenseType maps Elasticsearch license to one of the known and expected value.
func StrToElasticLicenseType(license string, logger logr.Logger) render.ElasticsearchLicenseType {
	if license == string(render.ElasticsearchLicenseTypeEnterprise) ||
		license == string(render.ElasticsearchLicenseTypeBasic) ||
		license == string(render.ElasticsearchLicenseTypeEnterpriseTrial) {
		return render.ElasticsearchLicenseType(license)
	}
	logger.V(3).Info("Elasticsearch license %s is unexpected", license)
	return render.ElasticsearchLicenseTypeUnknown
}
