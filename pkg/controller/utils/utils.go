// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/crypto"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/logstorage/esgateway"
)

const (
	// If this annotation is set on an object, the operator will ignore it, allowing user modifications.
	// This is for development and testing purposes only. Do not use this annotation
	// for production, as this will cause problems with upgrade.
	unsupportedIgnoreAnnotation = "unsupported.operator.tigera.io/ignore"

	TigeraElasticsearchUserSecretLabel = "tigera-elasticsearch-user"
	DefaultElasticsearchShards         = 1

	// Mark any secret containing credentials for ES gateway with this label key/value. This will allow ES gateway to watch only the
	// releveant secrets it needs.
	ESGatewaySelectorLabel      = "esgateway.tigera.io/secrets"
	ESGatewaySelectorLabelValue = "credentials"
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
	return AddNamespacedWatch(c, s, metaMatches...)
}

func AddConfigMapWatch(c controller.Controller, name, namespace string) error {
	cm := &v1.ConfigMap{
		TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	return AddNamespacedWatch(c, cm)
}

func AddServiceWatch(c controller.Controller, name, namespace string) error {
	return AddNamespacedWatch(c, &v1.Service{
		TypeMeta:   metav1.TypeMeta{Kind: "Service", APIVersion: "V1"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	})
}

func addLicenseWatch(c controller.Controller) error {
	lic := &v3.LicenseKey{
		TypeMeta: metav1.TypeMeta{Kind: "LicenseKey"},
	}
	return c.Watch(&source.Kind{Type: lic}, &handler.EnqueueRequestForObject{})
}

// WaitToAddLicenseKeyWatch will check if projectcalico.org APIs are available and if so, it will add a watch for LicenseKey
// The completion of this operation will be signaled on a ready channel
func WaitToAddLicenseKeyWatch(controller controller.Controller, client kubernetes.Interface, log logr.Logger, flag *ReadyFlag) {
	maxDuration := 30 * time.Second
	duration := 1 * time.Second
	ticker := time.NewTicker(duration)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			duration = duration * 2
			if duration >= maxDuration {
				duration = maxDuration
			}
			ticker.Reset(duration)
			if isLicenseKeyReady(client) {
				err := addLicenseWatch(controller)
				if err != nil {
					log.Info("failed to watch LicenseKey resource: %v. Will retry to add watch", err)
				} else {
					flag.MarkAsReady()
					return
				}
			}
		}
	}
}

// AddNamespacedWatch creates a watch on the given object. If a name and namespace are provided, then it will
// use predicates to only return matching objects. If they are not, then all events of the provided kind
// will be generated.
func AddNamespacedWatch(c controller.Controller, obj client.Object, metaMatches ...MetaMatch) error {
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

func isLicenseKeyReady(client kubernetes.Interface) bool {
	_, res, err := client.Discovery().ServerGroupsAndResources()
	if err != nil {
		return false
	}
	for _, group := range res {
		if group.GroupVersion == "projectcalico.org/v3" {
			for _, r := range group.APIResources {
				if r.Kind == "LicenseKey" {
					return true
				}
			}
		}
	}
	return false
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

// GetK8sServiceEndPoint reads the kubernetes-service-endpoint configmap and pushes
// KUBERNETES_SERVICE_HOST, KUBERNETES_SERVICE_PORT to calico-node daemonset, typha
// apiserver deployments
func GetK8sServiceEndPoint(client client.Client) error {
	cmName := render.K8sSvcEndpointConfigMapName
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      cmName,
		Namespace: rmeta.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		// If the configmap is unavailable, do not return error
		if !kerrors.IsNotFound(err) {
			return fmt.Errorf("Failed to read ConfigMap %q: %s", cmName, err)
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
		err := c.Get(context.Background(), client.ObjectKey{Name: ps.Name, Namespace: rmeta.OperatorNamespace()}, s)
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

// CreateKubeControllersSecrets checks for the existence of the secrets necessary for Kube controllers to access Elasticsearch through ES gateway and
// creates them if they are missing. Kube controllers no longer uses admin credentials to make requests directly to Elasticsearch. Instead, gateway credentials
// are generated and stored in the user secret, a hashed version of the credentials is stored in the tigera-elasticsearch namespace for ES Gateway to retrieve and use to compare
// the gateway credentials, and a secret containing real admin level credentials is created and stored in the tigera-elasticsearch namespace to be swapped in once
// ES Gateway has confirmed that the gateway credentials match.
func CreateKubeControllersSecrets(ctx context.Context, esAdminUserSecret *corev1.Secret, cli client.Client) (*corev1.Secret, *corev1.Secret, *corev1.Secret, error) {
	kubeControllersGatewaySecret, err := GetSecret(ctx, cli, render.ElasticsearchKubeControllersUserSecret, rmeta.OperatorNamespace())
	if err != nil {
		return nil, nil, nil, err
	}
	if kubeControllersGatewaySecret == nil {
		password := crypto.GeneratePassword(16)
		kubeControllersGatewaySecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchKubeControllersUserSecret,
				Namespace: rmeta.OperatorNamespace(),
			},
			Data: map[string][]byte{
				"username": []byte(render.ElasticsearchKubeControllersUserName),
				"password": []byte(password),
			},
		}
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(kubeControllersGatewaySecret.Data["password"], bcrypt.MinCost)
	if err != nil {
		return nil, nil, nil, err
	}

	kubeControllersVerificationSecret, err := GetSecret(ctx, cli, render.ElasticsearchKubeControllersVerificationUserSecret, render.ElasticsearchNamespace)
	if err != nil {
		return nil, nil, nil, err
	}
	if kubeControllersVerificationSecret == nil {
		kubeControllersVerificationSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchKubeControllersVerificationUserSecret,
				Namespace: render.ElasticsearchNamespace,
				Labels: map[string]string{
					ESGatewaySelectorLabel: ESGatewaySelectorLabelValue,
				},
			},
			Data: map[string][]byte{
				"username": []byte(render.ElasticsearchKubeControllersUserName),
				"password": hashedPassword,
			},
		}
	}

	kubeControllersSecureUserSecret, err := GetSecret(ctx, cli, render.ElasticsearchKubeControllersSecureUserSecret, render.ElasticsearchNamespace)
	if err != nil {
		return nil, nil, nil, err
	}
	if kubeControllersSecureUserSecret == nil {
		kubeControllersSecureUserSecret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      render.ElasticsearchKubeControllersSecureUserSecret,
				Namespace: render.ElasticsearchNamespace,
				Labels: map[string]string{
					ESGatewaySelectorLabel: ESGatewaySelectorLabelValue,
				},
			},
			Data: map[string][]byte{
				"username": []byte("elastic"),
				"password": esAdminUserSecret.Data["elastic"],
			},
		}
	}

	return kubeControllersGatewaySecret, kubeControllersVerificationSecret, kubeControllersSecureUserSecret, nil
}

// GetESGatewayCertificateSecrets retrieves certificate secrets needed for ES Gateway to run or for
// components to communicate with Elasticsearch/Kibana through ES Gateway. The order of the secrets returned are:
// 1) The certificate/key secret to be mounted by ES Gateway and used to authenticate requests before
// proxying to Elasticsearch/Kibana (in the operator namespace). If the user didn't create this secret, it is created.
// 2) The certificate mounted by other clients that connect to Elasticsearch/Kibana through ES Gateway (in the operator namespace).
// The final return value is used to indicate that the certificate secret was provided by the customer. This
// ensures that we do not re-render the secret in the Operator Namespace and overwrite the OwnerReference.
func GetESGatewayCertificateSecrets(ctx context.Context, instl *operatorv1.InstallationSpec, cli client.Client, clusterDomain string) (*corev1.Secret, *corev1.Secret, bool, error) {
	var publicCertSecret *corev1.Secret

	svcDNSNames := dns.GetServiceDNSNames(render.ElasticsearchServiceName, render.ElasticsearchNamespace, clusterDomain)
	svcDNSNames = append(svcDNSNames, dns.GetServiceDNSNames(esgateway.ServiceName, render.ElasticsearchNamespace, clusterDomain)...)

	// Get the secret - might be nil
	oprKeyCert, err := GetSecret(ctx, cli, render.TigeraElasticsearchCertSecret, rmeta.OperatorNamespace())
	if err != nil {
		return nil, nil, false, err
	}

	// Ensure that cert is valid.
	oprKeyCert, err = EnsureCertificateSecret(render.TigeraElasticsearchCertSecret, oprKeyCert, corev1.TLSPrivateKeyKey, corev1.TLSCertKey, rmeta.DefaultCertificateDuration, svcDNSNames...)
	if err != nil {
		return nil, nil, false, err
	}

	// Three different certificate issuers are possible:
	// - The operator self-signed certificate
	// - A user's BYO keypair for Elastic (uncommon)
	// - The issuer that is provided through the certificate management feature.
	keyCertIssuer, err := GetCertificateIssuer(oprKeyCert.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, nil, false, err
	}
	customerProvidedCert := !IsOperatorIssued(keyCertIssuer)

	// If Certificate management is enabled, we only want to trust the CA cert and let the init container handle private key generation.
	if instl.CertificateManagement != nil {
		cmCa := instl.CertificateManagement.CACert
		cmIssuer, err := GetCertificateIssuer(cmCa)
		if err != nil {
			return nil, nil, false, err
		}

		// If the issuer of the current secret is not the same as the certificate management issuer and also is not
		// issued by the tigera-operator, it means that it is added to this cluster by the customer. This is not supported
		// in combination with certificate management.
		if customerProvidedCert && cmIssuer != keyCertIssuer {
			return nil, nil, false, fmt.Errorf("certificate management does not support custom Elasticsearch secrets, please delete secret %s/%s or disable certificate management", oprKeyCert.Namespace, oprKeyCert.Name)
		}

		oprKeyCert.Data[corev1.TLSCertKey] = instl.CertificateManagement.CACert
		publicCertSecret = render.CreateCertificateSecret(instl.CertificateManagement.CACert, relasticsearch.PublicCertSecret, rmeta.OperatorNamespace())
	} else {
		// Get the es gateway pub secret - might be nil
		publicCertSecret, err = GetSecret(ctx, cli, relasticsearch.PublicCertSecret, rmeta.OperatorNamespace())
		if err != nil {
			return nil, nil, false, err
		}

		if publicCertSecret != nil {
			// If the provided certificate secret (secret) is managed by the operator we need to check if the secret has the expected DNS names.
			// If it doesn't, delete the public secret so it can get recreated.
			if !customerProvidedCert {
				err = SecretHasExpectedDNSNames(publicCertSecret, corev1.TLSCertKey, svcDNSNames)
				if err == ErrInvalidCertDNSNames {
					if err := DeleteInvalidECKManagedPublicCertSecret(ctx, publicCertSecret, cli); err != nil {
						return nil, nil, false, err
					}
					publicCertSecret = render.CreateCertificateSecret(oprKeyCert.Data[corev1.TLSCertKey], relasticsearch.PublicCertSecret, rmeta.OperatorNamespace())
				}
			}
		} else {
			publicCertSecret = render.CreateCertificateSecret(oprKeyCert.Data[corev1.TLSCertKey], relasticsearch.PublicCertSecret, rmeta.OperatorNamespace())
		}
	}

	return oprKeyCert, publicCertSecret, customerProvidedCert, nil
}

// DeleteInvalidECKManagedPublicCertSecret deletes the given ECK managed cert secret.
func DeleteInvalidECKManagedPublicCertSecret(ctx context.Context, secret *corev1.Secret, cli client.Client) error {
	log.Info(fmt.Sprintf("Deleting invalid cert secret %q in %q namespace", secret.Name, secret.Namespace))
	return cli.Delete(ctx, secret)
}

func CalculateFlowShards(nodesSpecifications *operatorv1.Nodes, defaultShards int) int {
	if nodesSpecifications == nil || nodesSpecifications.ResourceRequirements == nil || nodesSpecifications.ResourceRequirements.Requests == nil {
		return defaultShards
	}

	var nodes = nodesSpecifications.Count
	var cores, _ = nodesSpecifications.ResourceRequirements.Requests.Cpu().AsInt64()
	var shardPerNode = int(cores) / 4

	if nodes <= 0 || shardPerNode <= 0 {
		return defaultShards
	}

	return int(nodes) * shardPerNode
}
