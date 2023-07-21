// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

package secrets

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/api/v1"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/render/logstorage/linseed"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// TenantControllers runs in multi-tenant mode and provisions a CA per-tenant, as well as generating
// per-tenant keypairs and a trusted bundle.
type TenantController struct {
	client        client.Client
	scheme        *runtime.Scheme
	status        status.StatusManager
	clusterDomain string
	multiTenant   bool
	log           logr.Logger
}

func AddTenantController(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.MultiTenant {
		return nil
	}

	r := &TenantController{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		clusterDomain: opts.ClusterDomain,
		status:        status.New(mgr.GetClient(), "secrets", opts.KubernetesVersion),
		log:           logf.Log.WithName("controller_tenant_secrets"),
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("tenant-secrets-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	if err = c.Watch(&source.Kind{Type: &operatorv1.Tenant{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("tenant-secrets-controller failed to watch Tenant resource: %w", err)
	}

	// TODO Watch all the secrets created by this controller so we can regenerate any that are deleted

	return nil
}

func (r *TenantController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logc := r.log.WithValues("Request.Namespace", request.Namespace)
	if request.Namespace == "" {
		// Tenant resources are always within a namespace.
		return reconcile.Result{}, nil
	}

	// Get the Tenant.
	tenant, err := utils.GetTenant(ctx, r.client, request.Namespace)
	if errors.IsNotFound(err) {
		// No tenant in this namespace. Ignore the update.
		logc.V(1).Info("No Tenant in this Namespace, skip")
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	} else if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Tenant", err, logc)
		return reconcile.Result{}, err
	}
	r.status.OnCRFound()

	// Get Installation resource.
	_, installation, err := utils.GetInstallation(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, logc)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, logc)
		return reconcile.Result{}, err
	}

	// Create a certificate manager for this tenant. This certificate manager will load the CA for this tenant, creating it if needed,
	// and can be used to sign any certificates needed for this tenant's components.
	opts := []certificatemanager.Option{
		certificatemanager.AllowCACreation(),
		certificatemanager.WithLogger(logc),
		certificatemanager.WithTenant(tenant),
	}
	cm, err := certificatemanager.CreateWithOptions(r.client, installation, r.clusterDomain, tenant.Namespace, opts...)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create CA", err, logc)
		return reconcile.Result{}, err
	}
	cm.AddToStatusManager(r.status, tenant.Namespace)

	// Create a server key pair for Linseed to present to clients.
	//
	// This fetches the existing key pair from the truth namespace if it exists, or generates a new one in-memory otherwise.
	// It will be provisioned into the cluster in the render stage later on.
	linseedDNSNames := dns.GetServiceDNSNames(render.LinseedServiceName, tenant.Namespace, r.clusterDomain)
	linseedKeyPair, err := cm.GetOrCreateKeyPair(r.client, render.TigeraLinseedSecret, tenant.Namespace, linseedDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, logc)
		return reconcile.Result{}, err
	}

	// Create a key pair for Linseed to use for tokens.
	linseedTokenKP, err := cm.GetOrCreateKeyPair(r.client, render.TigeraLinseedTokenSecret, tenant.Namespace, []string{"localhost"})
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Error creating TLS certificate", err, logc)
		return reconcile.Result{}, err
	}

	// Collect key pairs that need to be rendered into the Tenant's namespace.
	keyPairOptions := []rcertificatemanagement.KeyPairOption{
		rcertificatemanagement.NewKeyPairOption(cm.KeyPair(), true, true),
		rcertificatemanagement.NewKeyPairOption(linseedKeyPair, true, true),
		rcertificatemanagement.NewKeyPairOption(linseedTokenKP, true, true),
	}

	// Get the cluster-scoped CA certificate.
	clusterCA, err := cm.GetCertificate(r.client, certificatemanagement.CASecretName, common.OperatorNamespace())
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying CA certificate", err, logc)
		return reconcile.Result{}, err
	}

	// Create a trusted bundle for this tenant. This bundle is provided to the tenant pods so that they can verify
	// each other's certificates. Each tenant needs to trust:
	// - Certificates signed by its own CA
	// - Certificates signed by the cluster-scoped Tigera CA
	trustedBundle := cm.CreateTrustedBundle()
	trustedBundle.AddCertificates(clusterCA)

	component := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:      tenant.Namespace,
		TruthNamespace: tenant.Namespace,
		ServiceAccounts: []string{
			linseed.ServiceAccountName,
			render.ManagerServiceAccount,
		},
		KeyPairOptions: keyPairOptions,
		TrustedBundle:  trustedBundle,
	})

	hdler := utils.NewComponentHandler(logc, r.client, r.scheme, tenant)
	if err = hdler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, logc)
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}
