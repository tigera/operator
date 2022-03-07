// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package controllers

import (
	"context"

	"github.com/tigera/operator/pkg/controller/options"

	"github.com/go-logr/logr"
	"github.com/tigera/operator/pkg/controller/imageassurance"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ImageAssuranceReconciler reconciles a ImageAssurance object
type ImageAssuranceReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=operator.tigera.io,resources=imageassurances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=operator.tigera.io,resources=imageassurances/status,verbs=get;update;patch

func (r *ImageAssuranceReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	_ = r.Log.WithValues("imageassurance", req.NamespacedName)

	return ctrl.Result{}, nil
}

func (r *ImageAssuranceReconciler) SetupWithManager(mgr ctrl.Manager, opts options.AddOptions) error {
	return imageassurance.Add(mgr, opts)
}
