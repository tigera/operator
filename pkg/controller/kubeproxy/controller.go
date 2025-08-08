// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package kubeproxy

import (
	"context"
	"fmt"
	"strconv"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	crdv1 "github.com/tigera/operator/pkg/apis/crd.projectcalico.org/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
)

const (
	controllerName = "kubeproxy-controller"
	ResourceName   = "kubeproxy"
)

var log = logf.Log.WithName(controllerName)

// Add creates a new Reconciler Controller and adds it to the Manager. The Manager will set fields on the Controller
// and start it when the Manager is started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	statusManager := status.New(mgr.GetClient(), ResourceName, opts.KubernetesVersion)
	reconciler := newReconciler(mgr.GetClient(), mgr.GetScheme(), statusManager, opts.DetectedProvider, opts)

	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	if err = utils.AddInstallationWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch Installation resource: %w", controllerName, err)
	}

	if err = c.WatchObject(&crdv1.FelixConfiguration{}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("%s failed to watch for Felix Configuration resource: %w", controllerName, err)
	}

	if err = utils.AddKubeProxyWatch(c); err != nil {
		return fmt.Errorf("%s failed to watch for Kube Proxy resource: %w", controllerName, err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("kubeproxy-controller failed to watch TigeraStatus: %w", err)
	}

	// Perform periodic reconciliation. This acts as a backstop to catch reconcile issues,
	// and also makes sure we spot when things change that might not trigger a reconciliation.
	if err = utils.AddPeriodicReconcile(c, utils.PeriodicReconcileTime, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("kubeproxy-controller failed to create periodic reconcile watch: %w", err)
	}

	return nil
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(
	cli client.Client,
	schema *runtime.Scheme,
	statusMgr status.StatusManager,
	p operatorv1.Provider,
	opts options.AddOptions,
) *Reconciler {
	c := &Reconciler{
		cli:           cli,
		scheme:        schema,
		provider:      p,
		status:        statusMgr,
		clusterDomain: opts.ClusterDomain,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// blank assignment to verify that ReconcileConnection implements reconcile.Reconciler
var _ reconcile.Reconciler = &Reconciler{}

type Reconciler struct {
	cli           client.Client
	scheme        *runtime.Scheme
	provider      operatorv1.Provider
	status        status.StatusManager
	clusterDomain string
}

// Reconcile reads that state of the cluster for a kube-proxy object and makes changes based on the
// state read and what is in the Installation and FelixConfiguration CRs.
func (r *Reconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(2).Info("Reconciling KubeProxy")

	_, installationCR, err := utils.GetInstallation(ctx, r.cli)
	if err != nil {
		return reconcile.Result{}, err
	} else if installationCR == nil {
		return reconcile.Result{}, nil
	}

	if !installationCR.BPFInstallModeAuto() {
		// If BPFInstallMode is not Auto, we should clean up kubeproxy from tigerastatus and not reconcile kube-proxy.
		r.status.OnCRNotFound()
		return reconcile.Result{}, nil
	}

	r.status.AddDaemonsets([]types.NamespacedName{
		{
			Name:      utils.KubeProxyDaemonSetName,
			Namespace: utils.KubeProxyNamespace,
		},
	})
	// Mark resource found so we can report problems via tigerastatus
	r.status.OnCRFound()

	bpfAutoInstallReq, err := utils.BPFAutoInstallRequirements(r.cli, ctx, installationCR)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "bpfInstallMode is Auto but the requirements are not met", err, reqLogger)
		return reconcile.Result{}, err
	}

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&bpfAutoInstallReq.KubeProxyDs.ObjectMeta)

	felixCR, err := utils.GetFelixConfiguration(ctx, r.cli)
	if err != nil {
		return reconcile.Result{}, err
	} else if felixCR == nil {
		return reconcile.Result{}, nil
	}

	// If BPF enabled in FelixConfiguration (meaning the calico-node rollout is completed) and BPFInstallMode is Auto,
	// we should try to disable kube-proxy.
	if felixCR.Spec.BPFEnabled != nil && *felixCR.Spec.BPFEnabled {
		// 1. Check if kube-proxy is already disabled.
		kubeProxyDS := bpfAutoInstallReq.KubeProxyDs
		if kubeProxyDS.Spec.Template.Spec.NodeSelector != nil &&
			kubeProxyDS.Spec.Template.Spec.NodeSelector[render.DisableKubeProxyKey] == strconv.FormatBool(true) {
			return reconcile.Result{}, nil
		}

		// 2. Patch the kube-proxy DaemonSet with a disabling nodeSelector.
		// This step ensures that kube-proxy is disabled not only during BPF installation (fresh install or migration),
		// but also if an external operation - such as a manual upgrade or migration - overrides this setting.
		patchFrom := client.MergeFrom(kubeProxyDS.DeepCopy())
		if kubeProxyDS.Spec.Template.Spec.NodeSelector == nil {
			kubeProxyDS.Spec.Template.Spec.NodeSelector = make(map[string]string)
		}
		kubeProxyDS.Spec.Template.Spec.NodeSelector[render.DisableKubeProxyKey] = strconv.FormatBool(true)
		if err := r.cli.Patch(ctx, kubeProxyDS, patchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourcePatchError, "unable to add kube-proxy nodeSelector", err, reqLogger)
			return reconcile.Result{}, err

		}
	} else {
		// If the dataplane is not BPF, we'll try to re-enable kube-proxy:
		// 1. Check if kube-proxy DaemonSet is disabled.
		kubeProxyDS := bpfAutoInstallReq.KubeProxyDs
		if kubeProxyDS.Spec.Template.Spec.NodeSelector == nil ||
			kubeProxyDS.Spec.Template.Spec.NodeSelector[render.DisableKubeProxyKey] != strconv.FormatBool(true) {
			return reconcile.Result{}, nil
		}

		// 2. Re-enable kube-proxy by removing the disabling nodeSelector.
		patchFrom := client.MergeFrom(kubeProxyDS.DeepCopy())
		delete(kubeProxyDS.Spec.Template.Spec.NodeSelector, render.DisableKubeProxyKey)
		if err := r.cli.Patch(ctx, kubeProxyDS, patchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourcePatchError, "unable to remove kube-proxy nodeSelector", err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	r.status.ReadyToMonitor()
	r.status.ClearDegraded()
	return reconcile.Result{}, nil
}
