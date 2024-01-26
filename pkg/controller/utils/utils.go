// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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
	"os"
	"sort"
	"strings"
	"time"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/render"
)

const (
	// If this annotation is set on an object, the operator will ignore it, allowing user modifications.
	// This is for development and testing purposes only. Do not use this annotation
	// for production, as this will cause problems with upgrade.
	unsupportedIgnoreAnnotation = "unsupported.operator.tigera.io/ignore"
)

var (
	DefaultInstanceKey     = client.ObjectKey{Name: "default"}
	DefaultTSEEInstanceKey = client.ObjectKey{Name: "tigera-secure"}
	OverlayInstanceKey     = client.ObjectKey{Name: "overlay"}

	PeriodicReconcileTime = 5 * time.Minute

	// StandardRetry is the amount of time to wait beofre retrying a request in
	// most scenarios. Retries should be used sparingly, and only in extraordinary
	// circumstances. Use this as a default when retries are needed.
	StandardRetry = 30 * time.Second

	// AllowedSysctlKeys controls the allowed Sysctl keys can be set in Tuning plugin
	AllowedSysctlKeys = map[string]bool{
		"net.ipv4.tcp_keepalive_intvl":  true,
		"net.ipv4.tcp_keepalive_probes": true,
		"net.ipv4.tcp_keepalive_time":   true,
	}
)

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

func AddInstallationWatch(c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operatorv1.Installation{}}, &handler.EnqueueRequestForObject{})
}

func AddAPIServerWatch(c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operatorv1.APIServer{}}, &handler.EnqueueRequestForObject{})
}

func AddComplianceWatch(c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operatorv1.Compliance{}}, &handler.EnqueueRequestForObject{})
}

func AddNamespaceWatch(c controller.Controller, name string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	return c.Watch(&source.Kind{Type: ns}, &handler.EnqueueRequestForObject{})
}

type MetaMatch func(metav1.ObjectMeta) bool

func AddSecretsWatch(c controller.Controller, name, namespace string, metaMatches ...MetaMatch) error {
	return AddSecretsWatchWithHandler(c, name, namespace, &handler.EnqueueRequestForObject{}, metaMatches...)
}

func AddSecretsWatchWithHandler(c controller.Controller, name, namespace string, h handler.EventHandler, metaMatches ...MetaMatch) error {
	s := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	return AddNamespacedWatch(c, s, h, metaMatches...)
}

func AddConfigMapWatch(c controller.Controller, name, namespace string, h handler.EventHandler) error {
	cm := &corev1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	return AddNamespacedWatch(c, cm, h)
}

func AddServiceWatch(c controller.Controller, name, namespace string) error {
	return AddServiceWatchWithHandler(c, name, namespace, &handler.EnqueueRequestForObject{})
}

func AddServiceWatchWithHandler(c controller.Controller, name, namespace string, h handler.EventHandler) error {
	return AddNamespacedWatch(c, &corev1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}, h)
}

func AddDeploymentWatch(c controller.Controller, name, namespace string) error {
	return AddNamespacedWatch(c, &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{Kind: "Deployment", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}, &handler.EnqueueRequestForObject{})
}

func AddPeriodicReconcile(c controller.Controller, period time.Duration, handler handler.EventHandler) error {
	return c.Watch(&source.Channel{Source: createPeriodicReconcileChannel(period)}, handler)
}

// AddSecretWatchWithLabel adds a secret watch for secrets with the given label in the given namespace.
// If no namespace is provided, it watches cluster-wide.
func AddSecretWatchWithLabel(c controller.Controller, ns, label string) error {
	return c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			_, hasLabel := e.Object.GetLabels()[label]
			return (ns == "" || e.Object.GetNamespace() == ns) && hasLabel
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, hasLabel := e.ObjectNew.GetLabels()[label]
			return (ns == "" || e.ObjectNew.GetNamespace() == ns) && hasLabel
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, hasLabel := e.Object.GetLabels()[label]
			return (ns == "" || e.Object.GetNamespace() == ns) && hasLabel
		},
	})
}

// AddCSRWatchWithRelevancyFn adds a watch for CSRs with the given label. isRelevantFn is a function that returns true for
// items that are relevant to the caller.
func AddCSRWatchWithRelevancyFn(c controller.Controller, isRelevantFn func(*certificatesv1.CertificateSigningRequest) bool) error {
	return c.Watch(&source.Kind{Type: &certificatesv1.CertificateSigningRequest{}}, &handler.EnqueueRequestForObject{}, &predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			csr, ok := e.Object.(*certificatesv1.CertificateSigningRequest)
			return ok && isRelevantFn(csr)

		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			csr, ok := e.ObjectNew.(*certificatesv1.CertificateSigningRequest)
			return ok && isRelevantFn(csr)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// If a CSR is deleted, then the need for a certificate is no longer there and there is no need to sign anything.
			// Therefore, we discard this event. It is up to the issuer to re-issue a new CSR if needed.
			return false
		},
	})
}

func createPeriodicReconcileChannel(period time.Duration) chan event.GenericEvent {
	periodicReconcileEvents := make(chan event.GenericEvent)
	eventObject := &unstructured.Unstructured{}
	eventObject.SetName(fmt.Sprintf("periodic-%s-reconcile-event", period.String()))

	go func() {
		for range time.Tick(period) {
			periodicReconcileEvents <- event.GenericEvent{Object: eventObject}
		}
	}()

	return periodicReconcileEvents
}

func WaitToAddLicenseKeyWatch(controller controller.Controller, c kubernetes.Interface, log logr.Logger, flag *ReadyFlag) {
	WaitToAddResourceWatch(controller, c, log, flag, []client.Object{&v3.LicenseKey{TypeMeta: metav1.TypeMeta{Kind: v3.KindLicenseKey}}})
}

func WaitToAddPolicyRecommendationScopeWatch(controller controller.Controller, c kubernetes.Interface, log logr.Logger, flag *ReadyFlag) {
	WaitToAddResourceWatch(controller, c, log, flag, []client.Object{&v3.PolicyRecommendationScope{TypeMeta: metav1.TypeMeta{Kind: v3.KindPolicyRecommendationScope}}})
}

func WaitToAddNetworkPolicyWatches(controller controller.Controller, c kubernetes.Interface, log logr.Logger, policies []types.NamespacedName) {
	objs := []client.Object{}
	for _, policy := range policies {
		objs = append(objs, &v3.NetworkPolicy{
			TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{Name: policy.Name, Namespace: policy.Namespace},
		})
	}

	// The success of a NetworkPolicy watch is not a dependency for resources to be installed or function correctly.
	// Therefore, no ready flag is accepted or created for the watch.
	WaitToAddResourceWatch(controller, c, log, nil, objs)
}

func WaitToAddTierWatch(tierName string, controller controller.Controller, c kubernetes.Interface, log logr.Logger, flag *ReadyFlag) {
	obj := &v3.Tier{
		TypeMeta:   metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: tierName},
	}

	// The success of a Tier watch can be used as a signal that Tier queries will be resolved using the cache.
	WaitToAddResourceWatch(controller, c, log, flag, []client.Object{obj})
}

// AddNamespacedWatch creates a watch on the given object. If a name and namespace are provided, then it will
// use predicates to only return matching objects. If they are not, then all events of the provided kind
// will be generated. Updates that do not modify the object's generation (e.g., status and metadata) will be ignored.
func AddNamespacedWatch(c controller.Controller, obj client.Object, h handler.EventHandler, metaMatches ...MetaMatch) error {
	objMeta := obj.(metav1.ObjectMetaAccessor).GetObjectMeta()
	pred := createPredicateForObject(objMeta)
	return c.Watch(&source.Kind{Type: obj}, h, pred)
}

func IsAPIServerReady(client client.Client, l logr.Logger) bool {
	instance, msg, err := GetAPIServer(context.Background(), client)
	if err != nil {
		if kerrors.IsNotFound(err) {
			l.V(3).Info("APIServer resource does not exist")
			return false
		}
		l.Error(err, "Unable to retrieve APIServer resource", "msg", msg)
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

func GetLogCollector(ctx context.Context, cli client.Client) (*operatorv1.LogCollector, error) {
	logCollector := &operatorv1.LogCollector{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, logCollector)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return logCollector, nil
}

// FetchLicenseKey returns the license if it has been installed. It's useful
// to prevent rollout of TSEE components that might require it.
// It will return an error if the license is not installed/cannot be read
func FetchLicenseKey(ctx context.Context, cli client.Client) (v3.LicenseKey, error) {
	instance := &v3.LicenseKey{}
	err := cli.Get(ctx, DefaultInstanceKey, instance)
	return *instance, err
}

// IsFeatureActive return true if the feature is listed in LicenseStatusKey
func IsFeatureActive(license v3.LicenseKey, featureName string) bool {
	for _, v := range license.Status.Features {
		if v == featureName || v == "all" {
			return true
		}
	}

	return false
}

// ValidateCertPair checks if the given secret exists in the given
// namespace and if so that it contains key and cert fields. If an
// empty string is passed for the keyName argument it is skipped.
// If a secret exists then it is returned. If there is an error
// accessing the secret (except NotFound) or the cert does not have
// both a key and cert field then an appropriate error is returned.
// If no secret exists then nil, nil is returned to represent that no
// cert is valid.
func ValidateCertPair(client client.Client, namespace, certPairSecretName, keyName, certName string) (*corev1.Secret, error) {
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

	if keyName != "" {
		if val, ok := secret.Data[keyName]; !ok || len(val) == 0 {
			return secret, fmt.Errorf("Secret %q does not have a field named %q", certPairSecretName, keyName)
		}
	}

	if val, ok := secret.Data[certName]; !ok || len(val) == 0 {
		return secret, fmt.Errorf("Secret %q does not have a field named %q", certPairSecretName, certName)
	}

	return secret, nil
}

// GetK8sServiceEndPoint returns the kubernetes-service-endpoint configmap
func GetK8sServiceEndPoint(client client.Client) (*corev1.ConfigMap, error) {
	cmName := render.K8sSvcEndpointConfigMapName
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      cmName,
		Namespace: common.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		return nil, err
	}
	return cm, nil
}

// PopulateK8sServiceEndPoint reads the kubernetes-service-endpoint configmap and pushes
// KUBERNETES_SERVICE_HOST, KUBERNETES_SERVICE_PORT to calico-node daemonset, typha
// apiserver deployments
func PopulateK8sServiceEndPoint(client client.Client) error {
	cm, err := GetK8sServiceEndPoint(client)
	if err != nil {
		if !kerrors.IsNotFound(err) {
			// If the configmap is unavailable, do not return an error
			return fmt.Errorf("Failed to read ConfigMap %q: %s", render.K8sSvcEndpointConfigMapName, err)
		}
	} else {
		k8sapi.Endpoint.Host = cm.Data["KUBERNETES_SERVICE_HOST"]
		k8sapi.Endpoint.Port = cm.Data["KUBERNETES_SERVICE_PORT"]
	}
	return nil
}

func GetNetworkingPullSecrets(i *operatorv1.InstallationSpec, c client.Client) ([]*corev1.Secret, error) {
	secrets := []*corev1.Secret{}
	for _, ps := range i.ImagePullSecrets {
		s := &corev1.Secret{}
		err := c.Get(context.Background(), client.ObjectKey{Name: ps.Name, Namespace: common.OperatorNamespace()}, s)
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

// GetTenant returns the Tenant instance in the given namespace.
func GetTenant(ctx context.Context, mt bool, cli client.Client, ns string) (*operatorv1.Tenant, string, error) {
	if !mt {
		// Multi-tenancy isn't enabled. Return nil.
		return nil, "", nil
	}

	key := client.ObjectKey{Name: "default", Namespace: ns}
	instance := &operatorv1.Tenant{}
	err := cli.Get(ctx, key, instance)
	if err != nil {
		return nil, "", err
	}

	if instance.Spec.ID == "" {
		return nil, "", fmt.Errorf("Tenant %s/%s has no ID specified", ns, instance.Name)
	}
	return instance, instance.Spec.ID, nil
}

// TenantNamespaces returns all namespaces that contain a tenant.
func TenantNamespaces(ctx context.Context, cli client.Client) ([]string, error) {
	namespaces := []string{}
	tenants := operatorv1.TenantList{}
	err := cli.List(ctx, &tenants)
	if err != nil {
		return nil, err
	}
	for _, t := range tenants.Items {
		namespaces = append(namespaces, t.Namespace)
	}

	// Sort the namespaces, so that the output is deterministic.
	sort.Strings(namespaces)
	return namespaces, nil
}

// GetInstallationStatus returns the current installation status, for use by other controllers.
func GetInstallationStatus(ctx context.Context, client client.Client) (*operatorv1.InstallationStatus, error) {
	// Fetch the Installation instance. We only support a single instance named "default".
	instance := &operatorv1.Installation{}
	if err := client.Get(ctx, DefaultInstanceKey, instance); err != nil {
		return nil, err
	}
	return &instance.Status, nil
}

// GetInstallation returns the current installation, for use by other controllers. It accounts for overlays and
// returns the variant according to status.Variant, which is leveraged by other controllers to know when it is safe to
// launch enterprise-dependent components.
func GetInstallation(ctx context.Context, client client.Client) (operatorv1.ProductVariant, *operatorv1.InstallationSpec, error) {
	// Fetch the Installation instance. We only support a single instance named "default".
	instance := &operatorv1.Installation{}
	if err := client.Get(ctx, DefaultInstanceKey, instance); err != nil {
		return instance.Status.Variant, nil, err
	}

	spec := instance.Spec

	// update Installation with 'overlay'
	overlay := operatorv1.Installation{}
	if err := client.Get(ctx, OverlayInstanceKey, &overlay); err != nil {
		if !apierrors.IsNotFound(err) {
			return instance.Status.Variant, nil, err
		}
	} else {
		spec = OverrideInstallationSpec(spec, overlay.Spec)
	}

	return instance.Status.Variant, &spec, nil
}

// GetAPIServer finds the correct API server instance and returns a message and error in the case of an error.
func GetAPIServer(ctx context.Context, client client.Client) (*operatorv1.APIServer, string, error) {
	// Fetch the APIServer instance. Look for the "default" instance first.
	instance := &operatorv1.APIServer{}
	err := client.Get(ctx, DefaultInstanceKey, instance)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, "failed to get apiserver 'default'", err
		}

		// Default instance doesn't exist. Check for the legacy (enterprise only) CR.
		err = client.Get(ctx, DefaultTSEEInstanceKey, instance)
		if err != nil {
			return nil, "failed to get apiserver 'tigera-secure'", err
		}
	} else {
		// Assert there is no legacy "tigera-secure" instance present.
		err = client.Get(ctx, DefaultTSEEInstanceKey, instance)
		if err == nil {
			return nil,
				"Duplicate configuration detected",
				fmt.Errorf("Multiple APIServer CRs provided. To fix, run \"kubectl delete apiserver tigera-secure\"")
		}
	}
	return instance, "", nil
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

type resourceWatchContext struct {
	predicate predicate.Predicate
	logger    logr.Logger
}

// WaitToAddResourceWatch will check if projectcalico.org APIs are available and if so, it will add a watch for resource
// The completion of this operation will be signaled on a ready channel
func WaitToAddResourceWatch(controller controller.Controller, c kubernetes.Interface, log logr.Logger, flag *ReadyFlag, objs []client.Object) {
	// Track resources left to watch and establish their watch context.
	resourcesToWatch := map[client.Object]resourceWatchContext{}
	for _, obj := range objs {
		resourcesToWatch[obj] = resourceWatchContext{
			predicate: createPredicateForObject(obj),
			logger:    ContextLoggerForResource(log, obj),
		}
	}

	maxDuration := 30 * time.Second
	duration := 1 * time.Second
	ticker := time.NewTicker(duration)
	defer ticker.Stop()
	for range ticker.C {
		duration = duration * 2
		if duration >= maxDuration {
			duration = maxDuration
		}
		ticker.Reset(duration)

		for obj := range resourcesToWatch {
			objLog := resourcesToWatch[obj].logger
			predicateFn := resourcesToWatch[obj].predicate
			if ok, err := isCalicoResourceReady(c, obj.GetObjectKind().GroupVersionKind().Kind); err != nil {
				msg := "Failed to check if resource is ready - will retry"
				if errors.IsNotFound(err) {
					objLog.WithValues("Error", err).V(2).Info(msg)
				} else {
					objLog.WithValues("Error", err).Info(msg)
				}
			} else if !ok {
				objLog.Info("Waiting for resource to be ready - will retry")
			} else if err := controller.Watch(&source.Kind{Type: obj}, &handler.EnqueueRequestForObject{}, predicateFn); err != nil {
				objLog.WithValues("Error", err).Info("Failed to watch resource - will retry")
			} else {
				objLog.V(2).Info("Successfully watching resource")
				delete(resourcesToWatch, obj)
			}
		}

		if len(resourcesToWatch) == 0 {
			if flag != nil {
				flag.MarkAsReady()
			}
			return
		}
	}
}

// isCalicoResourceReady checks if the specified resourceKind is available.
// the resourceKind must be of the calico resource group.
func isCalicoResourceReady(client kubernetes.Interface, resourceKind string) (bool, error) {
	// Only get the resources for the groupVersion we care about so that we are resilient to other
	// apiservices being down.
	res, err := client.Discovery().ServerResourcesForGroupVersion(v3.GroupVersionCurrent)
	if err != nil {
		return false, err
	}
	for _, r := range res.APIResources {
		if resourceKind == r.Kind {
			return true, nil
		}
	}
	return false, nil
}

// Creates a predicate for CRUD operations that matches the object's namespace, and name if provided.
// If neither name nor namespace is provided, all objects will be matched.
func createPredicateForObject(objMeta metav1.Object) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			if objMeta.GetName() == "" && objMeta.GetNamespace() == "" {
				// No name or namespace match was specified. Match everything.
				return true
			}
			if objMeta.GetName() != "" && e.Object.GetName() != objMeta.GetName() {
				// A name match was specified, and the object doesn't match.
				return false
			}

			// A name match was specified and the name matches, or this is just a namespace match.
			// Return a match if the namespaces match, or if no namespace match was given.
			return e.Object.GetNamespace() == objMeta.GetNamespace() || objMeta.GetNamespace() == ""
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Not all objects use/have a generation, so we can't always rely on that to determine if the
			// object has changed. The generation will be 0 if it's not set.
			generationChanged := e.ObjectOld.GetGeneration() == 0 || e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()

			if objMeta.GetName() == "" && objMeta.GetNamespace() == "" {
				// No name or namespace match was specified. Match everything, assuming the generation has changed.
				return generationChanged
			}

			if objMeta.GetName() != "" && e.ObjectNew.GetName() != objMeta.GetName() {
				// A name match was specified, and the object doesn't match it.
				return false
			}
			// A name match was specified and the name matches, or this is just a namespace match.
			// Assuming the generation has changed, return a match if the namespaces also match,
			// or if no namespace was given to match against.
			return generationChanged && (e.ObjectNew.GetNamespace() == objMeta.GetNamespace() || objMeta.GetNamespace() == "")
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			if objMeta.GetName() == "" && objMeta.GetNamespace() == "" {
				return true
			}
			if objMeta.GetName() != "" && e.Object.GetName() != objMeta.GetName() {
				return false
			}
			return e.Object.GetNamespace() == objMeta.GetNamespace() || objMeta.GetNamespace() == ""
		},
	}
}

// ValidateResourceNameIsQualified returns a compiled list of errors which states which rule the name
// did not respect. Returns nil if it's a valid name.
func ValidateResourceNameIsQualified(name string) error {
	errors := validation.IsDNS1123Subdomain(name)

	if len(errors) > 0 {
		return fmt.Errorf("%s is not a qualified resource name with errors: %s", name, strings.Join(errors[:], ", "))
	}

	return nil
}

// AddTigeraStatusWatch creates a watch on the given object. It uses predicates to only return matching objects.
func AddTigeraStatusWatch(c controller.Controller, name string) error {
	return c.Watch(&source.Kind{Type: &operatorv1.TigeraStatus{ObjectMeta: metav1.ObjectMeta{Name: name}}}, &handler.EnqueueRequestForObject{}, predicate.NewPredicateFuncs(func(object client.Object) bool {
		return object.GetName() == name
	}))
}

// GetKubeControllerMetricsPort fetches kube controller metrics port.
func GetKubeControllerMetricsPort(ctx context.Context, client client.Client) (int, error) {
	kubeControllersConfig := &crdv1.KubeControllersConfiguration{}
	kubeControllersMetricsPort := 0

	// Query the KubeControllersConfiguration object. We'll use this to help configure kube-controllers metric port.
	err := client.Get(ctx, types.NamespacedName{Name: "default"}, kubeControllersConfig)
	if err != nil && !apierrors.IsNotFound(err) {
		return 0, err
	}

	if kubeControllersConfig.Spec.PrometheusMetricsPort != nil {
		kubeControllersMetricsPort = *kubeControllersConfig.Spec.PrometheusMetricsPort
	}
	return kubeControllersMetricsPort, nil
}

func GetElasticsearch(ctx context.Context, c client.Client) (*esv1.Elasticsearch, error) {
	es := esv1.Elasticsearch{}
	err := c.Get(ctx, client.ObjectKey{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}, &es)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &es, nil
}

func IsNodeLocalDNSAvailable(ctx context.Context, cli client.Client) (bool, error) {
	ds := &appsv1.DaemonSet{}

	err := cli.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: "node-local-dns"}, ds)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		} else {
			return false, err
		}
	}

	return true, nil
}

// AddNodeLocalDNSWatch creates a watch on the node-local-dns pods.
func AddNodeLocalDNSWatch(c controller.Controller) error {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "node-local-dns",
		},
	}
	return c.Watch(&source.Kind{Type: &appsv1.DaemonSet{}}, &handler.EnqueueRequestForObject{}, createPredicateForObject(ds))
}

func GetDNSServiceIPs(ctx context.Context, client client.Client, provider operatorv1.Provider) ([]string, error) {
	// Discover the DNS Service's cluster IP address:
	// Default kubernetes dns service is named "kube-dns", but RKE2 is using a different name for the default
	// dns service i.e. "rke2-coredns-rke2-coredns".
	dnsServiceName := "kube-dns"
	if provider == operatorv1.ProviderRKE2 {
		dnsServiceName = "rke2-coredns-rke2-coredns"
	}

	kubeDNSService := &corev1.Service{}

	err := client.Get(ctx, types.NamespacedName{Name: dnsServiceName, Namespace: "kube-system"}, kubeDNSService)
	if err != nil {
		return nil, err
	}

	return kubeDNSService.Spec.ClusterIPs, nil
}

// GetDNSServiceName returns the name and namespace for the DNS service based on the given provider.
// This is "kube-dns" for most providers, but varies on OpenShift and RKE2.
func GetDNSServiceName(provider operatorv1.Provider) types.NamespacedName {
	kubeDNSServiceName := types.NamespacedName{Name: "kube-dns", Namespace: "kube-system"}
	if provider == operatorv1.ProviderOpenShift {
		kubeDNSServiceName = types.NamespacedName{Name: "dns-default", Namespace: "openshift-dns"}
	} else if provider == operatorv1.ProviderRKE2 {
		kubeDNSServiceName = types.NamespacedName{Name: "rke2-coredns-rke2-coredns", Namespace: "kube-system"}
	}
	return kubeDNSServiceName
}

// MonitorConfigMap starts a goroutine which exits if the given configmap's data is changed.
func MonitorConfigMap(cs kubernetes.Interface, name string, data map[string]string) error {
	informer := cache.NewSharedInformer(
		cache.NewListWatchFromClient(
			cs.CoreV1().RESTClient(),
			"configmaps",
			common.OperatorNamespace(),
			fields.OneTermEqualSelector("metadata.name", name),
		),
		&v1.ConfigMap{},
		0, // no resync period
	)
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) {
			if !compareMap(data, newObj.(*v1.ConfigMap).Data) {
				log.Info("detected config change. rebooting")
				os.Exit(0)
			}
			log.Info("ignoring configmap update as data was not modified")
		},
		AddFunc: func(obj interface{}) {
			if !compareMap(data, obj.(*v1.ConfigMap).Data) {
				log.Info("detected config creation change. rebooting")
				os.Exit(0)
			}
			log.Info("ignoring configmap creation as data was not modified")
		},
	})
	if err != nil {
		return err
	}

	go informer.Run(make(chan struct{}))
	for !informer.HasSynced() {
		time.Sleep(1 * time.Second)
	}
	return nil
}

func compareMap(m1, m2 map[string]string) bool {
	if len(m1) != len(m2) {
		return false
	}
	for k, v := range m1 {
		if m2[k] != v {
			return false
		}
	}
	return true
}

func IsDexDisabled(authentication *operatorv1.Authentication) bool {
	disableDex := false
	if authentication.Spec.OIDC != nil && authentication.Spec.OIDC.Type == operatorv1.OIDCTypeTigera {
		disableDex = true
	}
	return disableDex
}
func VerifySysctl(pluginData []operatorv1.Sysctl) error {
	for _, setting := range pluginData {
		if _, ok := AllowedSysctlKeys[setting.Key]; !ok {
			return fmt.Errorf("key %s is not allowed in spec.calicoNetwork.sysctl", setting.Key)
		}
	}
	return nil
}
