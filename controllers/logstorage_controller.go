// Copyright (c) 2020,2023 Tigera, Inc. All rights reserved.
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

	"github.com/tigera/operator/pkg/controller/logstorage/elastic"
	"github.com/tigera/operator/pkg/controller/logstorage/initializer"
	"github.com/tigera/operator/pkg/controller/logstorage/kubecontrollers"
	"github.com/tigera/operator/pkg/controller/logstorage/linseed"
	"github.com/tigera/operator/pkg/controller/logstorage/managedcluster"
	"github.com/tigera/operator/pkg/controller/logstorage/secrets"
	"github.com/tigera/operator/pkg/controller/logstorage/users"
	"github.com/tigera/operator/pkg/controller/options"
)

// LogStorageReconciler reconciles a LogStorage object
type LogStorageReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=operator.tigera.io,resources=logstorages,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=operator.tigera.io,resources=logstorages/status,verbs=get;update;patch

func (r *LogStorageReconciler) SetupWithManager(mgr ctrl.Manager, opts options.AddOptions) error {
	// Add all of the relevant log storage sub-controllers to the manager here.
	// Each of these controllers reconciles independently, but they work together in order to implement log storage
	// capabilities.
	if err := initializer.Add(mgr, opts); err != nil {
		return err
	}
	if err := initializer.AddConditionsController(mgr, opts); err != nil {
		return err
	}
	if err := secrets.Add(mgr, opts); err != nil {
		return err
	}
	if err := linseed.Add(mgr, opts); err != nil {
		return err
	}
	if err := elastic.Add(mgr, opts); err != nil {
		return err
	}
	if err := managedcluster.Add(mgr, opts); err != nil {
		return err
	}
	if err := users.Add(mgr, opts); err != nil {
		return err
	}
	if err := kubecontrollers.Add(mgr, opts); err != nil {
		return err
	}
	return nil
}
