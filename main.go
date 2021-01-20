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
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	goruntime "runtime"

	"github.com/cloudflare/cfssl/log"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	operatorv1 "github.com/tigera/operator/api/v1"
	operatorv1beta1 "github.com/tigera/operator/api/v1beta1"
	"github.com/tigera/operator/controllers"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/awssgsetup"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/version"
	// +kubebuilder:scaffold:imports
)

var (
	defaultMetricsPort int32 = 8484
	scheme                   = runtime.NewScheme()
	setupLog                 = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(operatorv1.AddToScheme(scheme))
	utilruntime.Must(operatorv1beta1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
	utilruntime.Must(apis.AddToScheme(scheme))
}

func printVersion() {
	log.Info(fmt.Sprintf("Version: %v", version.VERSION))
	log.Info(fmt.Sprintf("Go Version: %s", goruntime.Version()))
	log.Info(fmt.Sprintf("Go OS/Arch: %s/%s", goruntime.GOOS, goruntime.GOARCH))
	// TODO: Add this back if we can
	//log.Info(fmt.Sprintf("Version of operator-sdk: %v", sdkVersion.Version))
}

func main() {
	var enableLeaderElection bool
	// urlOnlyKubeconfig is a slight hack; we need to get the apiserver from the
	// kubeconfig but should use the in-cluster service account
	var urlOnlyKubeconfig string
	var showVersion bool
	var sgSetup bool
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&urlOnlyKubeconfig, "url-only-kubeconfig", "",
		"Path to a kubeconfig, but only for the apiserver url.")
	flag.BoolVar(&showVersion, "version", false,
		"Show version information")
	flag.BoolVar(&sgSetup, "aws-sg-setup", false,
		"Setup Security Groups in AWS (should only be used on OpenShift).")
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
		fmt.Println(components.GetReference(components.ComponentDex, "", ""))
		os.Exit(0)
	}

	if urlOnlyKubeconfig != "" {
		if err := setKubernetesServiceEnv(urlOnlyKubeconfig); err != nil {
			setupLog.Error(err, "Terminating")
			os.Exit(1)
		}
	}

	printVersion()

	ctx := context.Background()

	if sgSetup {
		log.Info("Setting up AWS Security Groups")
		cfg, err := config.GetConfig()
		if err != nil {
			log.Error(err, "")
			os.Exit(1)
		}

		client, err := client.New(cfg, client.Options{})
		if err != nil {
			log.Error(err, "")
			os.Exit(1)
		}

		err = awssgsetup.SetupAWSSecurityGroups(ctx, client)
		if err != nil {
			log.Error(err, "")
			os.Exit(1)
		}
		os.Exit(0)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr(),
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "operator-lock",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to get client for auto provider discovery")
		os.Exit(1)
	}

	// Attempt to auto discover the provider
	provider, err := utils.AutoDiscoverProvider(ctx, clientset)
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

	options := options.AddOptions{
		DetectedProvider:    provider,
		EnterpriseCRDExists: enterpriseCRDExists,
		AmazonCRDExists:     amazonCRDExists,
	}

	err = controllers.AddToManager(mgr, options)
	if err != nil {
		setupLog.Error(err, "unable to create controllers")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}

}

// setKubernetesServiceEnv configured the environment with the location of the Kubernetes API
// based on the provided kubeconfig file. We need this since we can't rely on the kube-proxy being present,
// since this operator may be the one installing the proxy! It's based off of logic in the cluster-network-operator.
// https://github.com/openshift/cluster-network-operator/blob/4d8a780f7b0f8b6a258aaba002a77d3313fa8fc8/cmd/cluster-network-operator/main.go#L32-L72
func setKubernetesServiceEnv(kubeconfigFile string) error {
	kubeconfig, err := clientcmd.LoadFromFile(kubeconfigFile)
	if err != nil {
		return err
	}
	clusterName := kubeconfig.Contexts[kubeconfig.CurrentContext].Cluster
	apiURL := kubeconfig.Clusters[clusterName].Server

	url, err := url.Parse(apiURL)
	if err != nil {
		return err
	}

	// The kubernetes in-cluster functions don't let you override the apiserver
	// directly; gotta "pass" it via environment vars.
	log.Info("Overriding kubernetes api to %s", apiURL)
	os.Setenv("KUBERNETES_SERVICE_HOST", url.Hostname())
	os.Setenv("KUBERNETES_SERVICE_PORT", url.Port())
	return nil
}

// metricsAddr processes user-specified metrics host and port and sets
// default values accordingly.
func metricsAddr() string {
	metricsHost := os.Getenv("METRICS_HOST")
	metricsPort := os.Getenv("METRICS_PORT")

	// if neither are specified, disable metrics.
	if metricsHost == "" && metricsPort == "" {
		// the controller-runtime accepts '0' to denote that metrics should be disabled.
		return "0"
	}
	// if just a host is specified, listen on port 8484 of that host.
	if metricsHost != "" && metricsPort == "" {
		// the controller-runtime will choose a random port if none is specified.
		// so use the defaultMetricsPort in that case.
		return fmt.Sprintf("%s:%d", metricsHost, defaultMetricsPort)
	}

	// finally, handle cases where just a port is specified or both are specified in the same case
	// since controller-runtime correctly uses all interfaces if no host is specified.
	return fmt.Sprintf("%s:%s", metricsHost, metricsPort)
}
