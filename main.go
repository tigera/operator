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

package main

import (
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/controllers"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/version"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(operatorv1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	// urlOnlyKubeconfig is a slight hack; we need to get the apiserver from the
	// kubeconfig but should use the in-cluster service account
	var urlOnlyKubeconfig string
	var showVersion bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&urlOnlyKubeconfig, "url-only-kubeconfig", "",
		"Path to a kubeconfig, but only for the apiserver url.")
	flag.BoolVar(&showVersion, "version", false,
		"Show version information")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.WriteTo(os.Stdout), zap.UseFlagOptions(&opts)))

	if showVersion {
		fmt.Println("Operator:", version.VERSION)
		fmt.Println(components.GetReference(components.ComponentCalicoNode, "", ""))
		fmt.Println(components.GetReference(components.ComponentCalicoCNI, "", ""))
		fmt.Println(components.GetReference(components.ComponentCalicoTypha, "", ""))
		fmt.Println(components.GetReference(components.ComponentCalicoKubeControllers, "", ""))
		fmt.Println(components.GetReference(components.ComponentFlexVolume, "", ""))
		fmt.Println(components.GetReference(components.ComponentTigeraNode, "", ""))
		fmt.Println(components.GetReference(components.ComponentTigeraTypha, "", ""))
		fmt.Println(components.GetReference(components.ComponentTigeraKubeControllers, "", ""))
		fmt.Println(components.GetReference(components.ComponentCloudControllers, "", ""))
		fmt.Println(components.GetReference(components.ComponentAPIServer, "", ""))
		fmt.Println(components.GetReference(components.ComponentQueryServer, "", ""))
		fmt.Println(components.GetReference(components.ComponentComplianceController, "", ""))
		fmt.Println(components.GetReference(components.ComponentComplianceReporter, "", ""))
		fmt.Println(components.GetReference(components.ComponentComplianceServer, "", ""))
		fmt.Println(components.GetReference(components.ComponentComplianceSnapshotter, "", ""))
		fmt.Println(components.GetReference(components.ComponentComplianceBenchmarker, "", ""))
		fmt.Println(components.GetReference(components.ComponentIntrusionDetectionController, "", ""))
		fmt.Println(components.GetReference(components.ComponentElasticTseeInstaller, "", ""))
		fmt.Println(components.GetReference(components.ComponentManager, "", ""))
		fmt.Println(components.GetReference(components.ComponentManagerProxy, "", ""))
		fmt.Println(components.GetReference(components.ComponentGuardian, "", ""))
		fmt.Println(components.GetReference(components.ComponentFluentd, "", ""))
		fmt.Println(components.GetReference(components.ComponentEsCurator, "", ""))
		fmt.Println(components.GetReference(components.ComponentKibana, "", ""))
		fmt.Println(components.GetReference(components.ComponentElasticsearch, "", ""))
		os.Exit(0)
	}

	if urlOnlyKubeconfig != "" {
		if err := setKubernetesServiceEnv(urlOnlyKubeconfig); err != nil {
			setupLog.Error(err, "Terminating")
			os.Exit(1)
		}
	}

	printVersion()

	// Attempt to auto discover the provider
	provider, err := utils.AutoDiscoverProvider(ctx, mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "Auto discovery of Provider failed")
		os.Exit(1)
	}
	setupLog.WithValues("provider", provider).Info("Checking type of cluster")

	// Determine if we need to start the TSEE specific controllers.
	enterpriseCRDExists, err := utils.RequiresTigeraSecure(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "Failed to determine if TSEE is required")
		os.Exit(1)
	}
	setupLog.WithValues("required", enterpriseCRDExists).Info("Checking if TSEE controllers are required")

	amazonCRDExists, err := utils.RequiresAmazonController(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "Failed to determine if AmazonCloudIntegration is required")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "operator-lock",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controllers.InstallationReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Installation"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options.AddOptions{
		DetectedProvider:    provider,
		EnterpriseCRDExists: enterpriseCRDExists,
		AmazonCRDExists:     amazonCRDExists,
	}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Installation")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}

}
