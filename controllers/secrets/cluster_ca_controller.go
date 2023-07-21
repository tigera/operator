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
	"time"

	"github.com/go-logr/logr"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"

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

// SecretsController provisions all the necessary key pairs, secrets, and trusted CA bundles needed by
// the Calico installation.
type ClusterCAController struct {
	client        client.Client
	scheme        *runtime.Scheme
	clusterDomain string
	multiTenant   bool
	log           logr.Logger
}

func AddClusterCAController(mgr manager.Manager, opts options.AddOptions) error {
	r := &ClusterCAController{
		client:        mgr.GetClient(),
		scheme:        mgr.GetScheme(),
		clusterDomain: opts.ClusterDomain,
		log:           logf.Log.WithName("controller_cluster_ca"),
	}

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("cluster-ca-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource Installation
	if err = c.Watch(&source.Kind{Type: &operatorv1.Installation{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("cluster-ca-controller failed to watch primary resource: %w", err)
	}

	// TODO We should watch the CA secret we create as well.

	return nil
}

func (r *ClusterCAController) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logc := r.log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)

	// Get Installation resource.
	instance := &operatorv1.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, instance); err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		logc.Error(err, "An error occurred when querying the Installation resource")
		return reconcile.Result{}, err
	}

	// Create the cluster CA.
	opts := []certificatemanager.Option{
		certificatemanager.AllowCACreation(),
		certificatemanager.WithLogger(logc),
	}
	cm, err := certificatemanager.CreateWithOptions(r.client, &instance.Spec, r.clusterDomain, common.OperatorNamespace(), opts...)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Collect key pairs that need to be rendered into the Tenant's namespace.
	keyPairOptions := []rcertificatemanagement.KeyPairOption{
		rcertificatemanagement.NewKeyPairOption(cm.KeyPair(), true, false),
	}

	component := rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
		Namespace:      common.OperatorNamespace(),
		KeyPairOptions: keyPairOptions,
	})

	hdler := utils.NewComponentHandler(logc, r.client, r.scheme, instance)
	if err = hdler.CreateOrUpdateOrDelete(ctx, component, nil); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{RequeueAfter: 60 * time.Second}, nil
}
