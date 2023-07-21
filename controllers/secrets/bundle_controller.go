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

	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// SecretsController provisions all the necessary key pairs, secrets, and trusted CA bundles needed by
// the Calico installation.
type BundleController struct {
	client        client.Client
	scheme        *runtime.Scheme
	status        status.StatusManager
	clusterDomain string
	multiTenant   bool
	log           logr.Logger
}

func AddBundleController(mgr manager.Manager, opts options.AddOptions) error {
	if opts.MultiTenant {
		return nil
	}

	r := &BundleController{
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

	// Catch if something modifies the resources that this controller consumes.
	// TODO: Some of these should queue updates for all tenants.
	return nil
}

func (r *BundleController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	// TODO: Implement this for single-tenant bundle generation.
	return reconcile.Result{}, nil
}
