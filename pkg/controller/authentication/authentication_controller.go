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

package authentication

import (
	"context"
	"fmt"
	"time"

	oprv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_authentication")

const (
	ControllerName = "authentication-controller"
)

// Add creates a new authentication Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	return add(mgr, newReconciler(mgr, opts.DetectedProvider))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, provider oprv1.Provider) *ReconcileAuthentication {
	r := &ReconcileAuthentication{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		provider: provider,
		status:   status.New(mgr.GetClient(), "authentication"),
	}
	r.status.Run()
	return r
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r *ReconcileAuthentication) error {
	c, err := controller.New(ControllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", ControllerName, err)
	}

	err = c.Watch(&source.Kind{Type: &oprv1.Authentication{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch resource: %w", ControllerName, err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch installation resource: %w", ControllerName, err)
	}

	err = c.Watch(&source.Kind{Type: &oprv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch resource: %w", ControllerName, err)
	}

	for _, namespace := range []string{render.OperatorNamespace(), render.DexNamespace} {
		for _, secretName := range []string{
			render.DexTLSSecretName, render.OIDCSecretName, render.OpenshiftSecretName, render.DexObjectName,
		} {
			if err = utils.AddSecretsWatch(c, secretName, namespace); err != nil {
				return fmt.Errorf("%s failed to watch the secret '%s' in '%s' namespace: %w", ControllerName, secretName, namespace, err)
			}
		}
	}

	return nil
}

// blank assignment to verify that ReconcileAuthentication implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAuthentication{}

// ReconcileAuthentication reconciles an Authentication object
type ReconcileAuthentication struct {
	client   client.Client
	scheme   *runtime.Scheme
	provider oprv1.Provider
	status   status.StatusManager
}

// Reconciles the cluster state with the Authentication object that is found in the cluster.
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAuthentication) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ", "controller", ControllerName)

	ctx := context.Background()

	// Fetch the Authentication spec. If present, we deploy dex in the cluster.
	authentication, err := utils.GetAuthentication(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()
	reqLogger.V(2).Info("Loaded config", "config", authentication)

	// Set defaults for backwards compatibility.
	updateAuthenticationWithDefaults(authentication)

	// Validate the configuration
	if err := validateAuthentication(authentication); err != nil {
		r.status.SetDegraded("Invalid Authentication provided", err.Error())
		return reconcile.Result{}, err
	}

	// Write the authentication back to the datastore, so the controllers depending on this can reconcile.
	if err := r.client.Update(ctx, authentication); err != nil {
		log.Error(err, "Failed to write defaults")
		r.status.SetDegraded("Failed to write defaults", err.Error())
		return reconcile.Result{}, err
	}

	// Query for the installation object.
	installationCR, err := installation.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Error(err, "Installation not found")
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		log.Error(err, "Error querying installation")
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}
	if installationCR.Status.Variant != oprv1.TigeraSecureEnterprise {
		log.Error(err, fmt.Sprintf("Waiting for network to be %s", oprv1.TigeraSecureEnterprise))
		r.status.SetDegraded(fmt.Sprintf("Waiting for network to be %s", oprv1.TigeraSecureEnterprise), "")
		return reconcile.Result{}, nil
	}

	// Make sure the tigera-dex namespace exists, before rendering any objects there.
	if err := r.client.Get(ctx, client.ObjectKey{Name: render.DexObjectName}, &corev1.Namespace{}); err != nil {
		if errors.IsNotFound(err) {
			log.Error(err, "Waiting for namespace tigera-dex to be created")
			r.status.SetDegraded("Waiting for namespace tigera-dex to be created", err.Error())
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		} else {
			log.Error(err, "Error querying tigera-dex namespace")
			r.status.SetDegraded("Error querying tigera-dex namespace", err.Error())
			return reconcile.Result{}, err
		}
	}

	// Make sure Authentication and ManagementClusterConnection are not present at the same time.
	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if managementClusterConnection != nil {
		log.Error(err, "Only one of Authentication and ManagementClusterConnection may be specified")
		r.status.SetDegraded("Only one of Authentication and ManagementClusterConnection may be specified", err.Error())
		return reconcile.Result{}, err
	} else if err != nil {
		log.Error(err, "Error querying ManagementClusterConnection")
		r.status.SetDegraded("Error querying ManagementClusterConnection", err.Error())
		return reconcile.Result{}, err
	}

	// Cert used for TLS between voltron and dex when voltron is proxying dex from https://<manager-url>/dex
	tlsSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexTLSSecretName, Namespace: render.OperatorNamespace()}, tlsSecret); err != nil {
		if errors.IsNotFound(err) {
			// We need to render a new one.
			tlsSecret = render.CreateDexTLSSecret()
		} else {
			log.Error(err, "Failed to read tigera-operator/tigera-dex-tls secret")
			r.status.SetDegraded("Failed to read tigera-operator/tigera-dex-tls secret", err.Error())
			return reconcile.Result{}, err
		}
	}

	// Dex will be configured with the contents of this secret, such as clientID and clientSecret.
	idpSecret, err := getIdpSecret(ctx, r.client, authentication)
	if err != nil {
		log.Error(err, "Invalid or missing identity provider secret")
		r.status.SetDegraded("Invalid or missing identity provider secret", err.Error())
		return reconcile.Result{}, err
	}

	// Set namespace for secrets so they can be used in the namespace of dex.
	idpSecret = render.CopySecrets(render.DexNamespace, idpSecret)[0]

	dexSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.DexObjectName, Namespace: render.OperatorNamespace()}, dexSecret); err != nil {
		if errors.IsNotFound(err) {
			// We need to render a new one.
			dexSecret = render.CreateDexClientSecret()
		} else {
			log.Error(err, "Failed to read tigera-operator/tigera-dex secret")
			r.status.SetDegraded("Failed to read tigera-operator/tigera-dex secret", err.Error())
			return reconcile.Result{}, err
		}
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installationCR, r.client)
	if err != nil {
		log.Error(err, "Error retrieving pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	// DexConfig adds convenience methods around dex related objects in k8s and can be used to configure Dex.
	dexCfg := render.NewDexConfig(authentication, tlsSecret, dexSecret, idpSecret)

	// Create a component handler to manage the rendered component.
	hlr := utils.NewComponentHandler(log, r.client, r.scheme, authentication)

	// Render the desired objects from the CRD and create or update them.
	reqLogger.V(3).Info("rendering components")
	component := render.Dex(
		pullSecrets,
		r.provider == oprv1.ProviderOpenShift,
		installationCR.Status.Computed,
		dexCfg,
	)

	if err := hlr.CreateOrUpdate(context.Background(), component, r.status); err != nil {
		log.Error(err, "Error creating / updating resource")
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Everything is available - update the CRD status.
	authentication.Status.State = oprv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, authentication); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func getIdpSecret(ctx context.Context, client client.Client, authentication *oprv1.Authentication) (*corev1.Secret, error) {
	var secretName string

	if authentication.Spec.OIDC != nil {
		secretName = render.OIDCSecretName
	} else {
		secretName = render.OpenshiftSecretName
	}

	secret := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Name: secretName, Namespace: render.OperatorNamespace()}, secret); err != nil {
		return nil, fmt.Errorf("missing secret %s/%s: %w", render.OperatorNamespace(), secretName, err)
	}

	if len(secret.Data[render.ClientIDSecretField]) == 0 {
		return nil, fmt.Errorf("clientID is a required field for secret %s/%s", secret.Namespace, secret.Name)
	}

	if len(secret.Data[render.ClientSecretSecretField]) == 0 {
		return nil, fmt.Errorf("clientSecret is a required field for secret %s/%s", secret.Namespace, secret.Name)
	}

	if authentication.Spec.Openshift != nil && len(secret.Data[render.RootCASecretField]) == 0 {
		return nil, fmt.Errorf("rootCA is a required field for secret %s/%s", secret.Namespace, secret.Name)
	}
	return secret, nil
}

// updateAuthenticationWithDefaults sets values for backwards compatibility.
func updateAuthenticationWithDefaults(authentication *oprv1.Authentication) {
	if authentication.Spec.OIDC != nil {
		if authentication.Spec.OIDC.UsernamePrefix != "" && authentication.Spec.UsernamePrefix == "" {
			authentication.Spec.UsernamePrefix = authentication.Spec.OIDC.UsernamePrefix
		}
		if authentication.Spec.OIDC.GroupsPrefix != "" && authentication.Spec.GroupsPrefix == "" {
			authentication.Spec.GroupsPrefix = authentication.Spec.OIDC.GroupsPrefix
		}
		if authentication.Spec.OIDC.EmailVerification == nil {
			defaultVerification := oprv1.EmailVerificationTypeVerify
			authentication.Spec.OIDC.EmailVerification = &defaultVerification
		}
	}
}

// validateAuthentication makes sure that the authentication spec is ready for use.
func validateAuthentication(authentication *oprv1.Authentication) error {
	// We support using only one connector at once.
	if authentication.Spec.OIDC != nil && authentication.Spec.Openshift != nil {
		return fmt.Errorf("multiple identity provider connectors were specified, but only 1 is allowed in the Authentication spec")
	} else if authentication.Spec.OIDC == nil && authentication.Spec.Openshift == nil {
		return fmt.Errorf("no identity provider connector was specified, please add a connector to the Authentication spec")
	}

	// If the user has specified the deprecated and the new prefix field, but with different values, we cannot proceed.
	if authentication.Spec.OIDC != nil {
		if authentication.Spec.OIDC.UsernamePrefix != "" && authentication.Spec.UsernamePrefix != "" && authentication.Spec.OIDC.UsernamePrefix != authentication.Spec.UsernamePrefix {
			return fmt.Errorf("you set username prefix twice, but with different values, please remove Authentication.Spec.OIDC.UsernamePrefix")
		}

		if authentication.Spec.OIDC.GroupsPrefix != "" && authentication.Spec.GroupsPrefix != "" && authentication.Spec.OIDC.GroupsPrefix != authentication.Spec.GroupsPrefix {
			return fmt.Errorf("you set groups prefix twice, but with different values, please remove Authentication.Spec.OIDC.GroupsPrefix")
		}

	}
	return nil
}
