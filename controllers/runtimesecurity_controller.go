// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package controllers

import (
	"context"

	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/runtimesecurity"

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RuntimeSecurityReconciler reconciles a RuntimeSecurity object
type RuntimeSecurityReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=operator.tigera.io,resources=runtimesecurities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=operator.tigera.io,resources=runtimesecurities/status,verbs=get;update;patch

func (r *RuntimeSecurityReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	_ = r.Log.WithValues("runtimesecurity", req.NamespacedName)

	return ctrl.Result{}, nil
}

func (r *RuntimeSecurityReconciler) SetupWithManager(mgr ctrl.Manager, opts options.AddOptions) error {
	return runtimesecurity.Add(mgr, opts)
}
