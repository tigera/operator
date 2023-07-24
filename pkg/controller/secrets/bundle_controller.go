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

	"github.com/go-logr/logr"

	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// BundleController is responsible for provisioning trusted bundles into each Tigera namespace.
type BundleController struct {
	client        client.Client
	scheme        *runtime.Scheme
	status        status.StatusManager
	clusterDomain string
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
		log:           logf.Log.WithName("controller_ca_bundle"),
	}
	r.status.Run(opts.ShutdownContext)

	return nil
}

func (r *BundleController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	// TODO: Implement this for single-tenant bundle generation.
	return reconcile.Result{}, nil
}
