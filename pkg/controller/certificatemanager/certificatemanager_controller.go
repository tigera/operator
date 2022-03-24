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
	"time"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const controllerName = "certificatemanager_controller"

// Add creates a new certificate manager Controller and adds it to the Manager.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	return add(mgr, newReconciler(mgr, opts))
}

// newReconciler returns a new reconcile.Reconciler that will ensure that a tigera-ca-private secret is created in the
// tigera-operator namespace if necessary.
func newReconciler(mgr manager.Manager, opts options.AddOptions) *ReconcileCertificateManager {
	statusManager := status.New(mgr.GetClient(), "ca-certificate", opts.KubernetesVersion)
	statusManager.Run(opts.ShutdownContext)
	return &ReconcileCertificateManager{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		watches:       make(map[runtime.Object]struct{}),
		status:        statusManager,
		clusterDomain: opts.ClusterDomain,
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r *ReconcileCertificateManager) error {
	c, err := controller.New(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	err = c.Watch(&source.Kind{Type: &operator.Installation{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("%s failed to watch installation resource: %w", controllerName, err)
	}

	if err = utils.AddSecretsWatch(c, certificatemanagement.CASecretName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("%s failed to watch Secret resource %s: %w", controllerName, certificatemanagement.CASecretName, err)
	}
	return nil
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

func (r *ReconcileCertificateManager) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	installation := &operator.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, installation); err != nil {
		if errors.IsNotFound(err) {
			log.Error(err, "Installation config not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		log.Error(err, "An error occurred when querying the Installation resource")
		return reconcile.Result{}, err
	}

	certificateManager, err := Create(r.client, &installation.Spec, r.clusterDomain)
	if err != nil {
		log.Error(err, "unable to create the Tigera CA")
		r.status.SetDegraded("Unable to create the Tigera CA", err.Error())
		return reconcile.Result{}, err
	}

	component := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:       common.OperatorNamespace(),
		ServiceAccounts: []string{},
		KeyPairOptions: []rcertificatemanagement.KeyPairOption{
			// this controller is responsible for rendering the tigera-ca-private secret.
			rcertificatemanagement.NewKeyPairOption(certificateManager.KeyPair(), true, false),
		},
	})

	hdl := utils.NewComponentHandler(log, r.client, r.scheme, installation)
	if err := hdl.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	r.status.ClearDegraded()

	r.status.ReadyToMonitor()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	return reconcile.Result{}, nil
}
