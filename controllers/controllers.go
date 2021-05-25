// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"fmt"

	"github.com/tigera/operator/pkg/controller/options"
	ctrl "sigs.k8s.io/controller-runtime"
)

func AddToManager(mgr ctrl.Manager, options options.AddOptions) error {
	if err := (&InstallationReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Installation"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Installation", err)
	}
	if err := (&APIServerReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("APIServer"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "APIServer", err)
	}
	if err := (&LogStorageReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("LogStorage"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "LogStorage", err)
	}
	if err := (&IntrusionDetectionReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("IntrusionDetection"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "IntrusionDetection", err)
	}
	if err := (&LogCollectorReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("LogCollector"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "LogCollector", err)
	}
	if err := (&ComplianceReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Compliance"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Compliance", err)
	}
	if err := (&MonitorReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Monitor"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Monitor", err)
	}
	if err := (&ManagerReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Manager"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Manager", err)
	}
	if err := (&ManagementClusterConnectionReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("ManagementClusterConnection"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "ManagementClusterConnection", err)
	}
	if err := (&AmazonCloudIntegrationReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("AmazonCloudIntegration"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "AmazonCloudIntegration", err)
	}
	if err := (&AuthenticationReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Authentication"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Authentication", err)
	}
	// +kubebuilder:scaffold:builder
	return nil
}
