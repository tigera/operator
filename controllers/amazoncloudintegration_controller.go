// Copyright (c) 2020-2024 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/controller/amazoncloudintegration"
	"github.com/tigera/operator/pkg/controller/options"
)

// AmazonCloudIntegrationReconciler reconciles a AmazonCloudIntegration object
type AmazonCloudIntegrationReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=operator.tigera.io,resources=amazoncloudintegrations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=operator.tigera.io,resources=amazoncloudintegrations/status,verbs=get;update;patch

//func (r *AmazonCloudIntegrationReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
//	_ = context.Background()
//	_ = r.Log.WithValues("amazoncloudintegration", req.NamespacedName)
//
//	// your logic here
//
//	return ctrl.Result{}, nil
//}

func (r *AmazonCloudIntegrationReconciler) SetupWithManager(mgr ctrl.Manager, opts options.AddOptions) error {
	return amazoncloudintegration.Add(mgr, opts)
	//return ctrl.NewControllerManagedBy(mgr).
	//	For(&operatorv1.AmazonCloudIntegration{}).
	//	Complete(r)
}
