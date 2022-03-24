// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package certificatemanager

import (
	"context"
	"fmt"

	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// Add creates a new certificate manager Controller and adds it to the Manager.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	ri, err := newReconciler(mgr, opts)
	if err != nil {
		return fmt.Errorf("failed to create certificate reconciler: %w", err)
	}
	return add(mgr, ri)
}

// newReconciler returns a new reconcile.Reconciler that will ensure that a tigera-ca-private secret is created in the
// tigera-operator namespace if necessary.
func newReconciler(mgr manager.Manager, opts options.AddOptions) (*ReconcileCertificateManager, error) {
	statusManager := status.New(mgr.GetClient(), "certificate", opts.KubernetesVersion)
	return &ReconcileCertificateManager{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		watches:       make(map[runtime.Object]struct{}),
		status:,
		clusterDomain: opts.ClusterDomain,
	}, nil
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r *ReconcileCertificateManager) error {

}

// ReconcileCertificateManager will ensure that a tigera-ca-private secret is created in the
// tigera-operator namespace if necessary.
type ReconcileCertificateManager struct {
	client        client.Client
	scheme        *runtime.Scheme
	watches       map[runtime.Object]struct{}
	status        status.StatusManager
	clusterDomain string
}

func (r *ReconcileCertificateManager) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	certificateManager, err := Create(r.client, &instance.Spec, r.clusterDomain)
	if err != nil {
		log.Error(err, "unable to create the Tigera CA")
		r.status.SetDegraded("Unable to create the Tigera CA", err.Error())
		return reconcile.Result{}, err
	}

}
