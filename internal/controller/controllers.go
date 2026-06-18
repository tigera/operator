// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

package controller

import (
	"fmt"

	"github.com/tigera/operator/pkg/controller/options"
	ctrl "sigs.k8s.io/controller-runtime"
)

func AddToManager(mgr ctrl.Manager, options options.ControllerOptions) error {
	// Controllers that run regardless of the dataplane mode. These are needed even when the
	// dataplane is disabled (spec.calicoNetwork.linuxDataplane: None, where no Calico
	// dataplane runs and the projectcalico.org/v3 API is never served):
	//   - Installation: the core controller; it renders the dataplane components only when a
	//     Linux dataplane is enabled, and reboots the operator (os.Exit(0)) if the dataplane
	//     mode changes so the correct controller set below is registered.
	//   - Istio, GatewayAPI: the standalone components an install with the dataplane disabled exists to support.
	//   - Secrets, CSR: certificate-management infrastructure other controllers rely on.
	if err := (&InstallationReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Installation"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Installation", err)
	}
	if err := (&IstioReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Istio"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller Istio: %v", err)
	}
	if err := (&GatewayAPIReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "GatewayAPI", err)
	}
	if err := (&SecretsReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Secrets"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "Secrets", err)
	}
	if err := (&CSRReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("CertificateSigningRequest"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "CSR", err)
	}

	// Dataplane- and v3-API-dependent controllers. None of these can function when the Linux
	// dataplane is disabled (the calico-system Tier, LicenseKey, and ClusterInformation they
	// read or wait on are never served, and the features they manage rely on a running Calico
	// dataplane), so they are not registered when the operator starts with the dataplane
	// disabled. If the dataplane mode changes at runtime, the Installation controller reboots
	// the operator and this set is (de)registered accordingly.
	if !options.DataplaneDisabled {
		if err := (&IPPoolReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("IPPool"),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "IPPool", err)
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
		if err := (&ApplicationLayerReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("ApplicationLayer"),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "ApplicationLayer", err)
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
		if err := (&NonClusterHostReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("NonClusterHost"),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "NonClusterHost", err)
		}
		if err := (&AuthenticationReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("Authentication"),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "Authentication", err)
		}
		if err := (&TiersReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("Tiers"),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "Tiers", err)
		}
		if err := (&PolicyRecommendationReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("PolicyRecommendation"),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "PolicyRecommendation", err)
		}
		if err := (&EgressGatewayReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("EgressGateway"),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "EgressGateway", err)
		}
		if err := (&WindowsReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("Windows"),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller Windows: %v", err)
		}
		if err := (&PacketCaptureReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("PacketCapture"),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "PacketCapture", err)
		}
		if err := (&WhiskerReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "Whisker", err)
		}
		if err := (&GoldmaneReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "Goldmane", err)
		}
		if err := (&KubeProxyReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "KubeProxy", err)
		}
		if err := (&PodIPRecoveryReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("controllers").WithName("PodIPRecovery"),
			Scheme: mgr.GetScheme(),
		}).SetupWithManager(mgr, options); err != nil {
			return fmt.Errorf("failed to create controller %s: %v", "PodIPRecovery", err)
		}
	}
	// +kubebuilder:scaffold:builder
	return nil
}
