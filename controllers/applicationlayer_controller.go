// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

	"github.com/tigera/operator/pkg/controller/applicationlayer"
	"github.com/tigera/operator/pkg/controller/options"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ApplicationLayerReconciler reconciles a ApplicationLayer object
type ApplicationLayerReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=operator.tigera.io,resources=applicationlayers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=operator.tigera.io,resources=applicationlayers/status,verbs=get;update;patch

func (r *ApplicationLayerReconciler) SetupWithManager(mgr ctrl.Manager, opts options.AddOptions) error {
	return applicationlayer.Add(mgr, opts)
}
