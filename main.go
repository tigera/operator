// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	goruntime "runtime"
	"strings"

	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/cache"

	"github.com/cloudflare/cfssl/log"
	"github.com/ghodss/yaml"
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

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	operatorv1beta1 "github.com/tigera/operator/api/v1beta1"
	"github.com/tigera/operator/controllers"
	"github.com/tigera/operator/pkg/active"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/awssgsetup"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/crds"
	"github.com/tigera/operator/pkg/dns"
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
	utilruntime.Must(apiextensions.AddToScheme(scheme))
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
	// log.Info(fmt.Sprintf("Version of operator-sdk: %v", sdkVersion.Version))
}

func main() {
	var enableLeaderElection bool
	// urlOnlyKubeconfig is a slight hack; we need to get the apiserver from the
	// kubeconfig but should use the in-cluster service account
	var urlOnlyKubeconfig string
	var showVersion bool
	var printImages string
	var printCalicoCRDs string
	var printEnterpriseCRDs string
	var sgSetup bool
	var manageCRDs bool
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&urlOnlyKubeconfig, "url-only-kubeconfig", "",
		"Path to a kubeconfig, but only for the apiserver url.")
	flag.BoolVar(&showVersion, "version", false,
		"Show version information")
	flag.StringVar(&printImages, "print-images", "",
		"Print the default images the operator could deploy and exit. Possible values: list")
	flag.StringVar(&printCalicoCRDs, "print-calico-crds", "",
		"Print the Calico CRDs the operator has bundled then exit. Possible values: all, <crd prefix>. If a value other than 'all' is specified, the first CRD with a prefix of the specified value will be printed.")
	flag.StringVar(&printEnterpriseCRDs, "print-enterprise-crds", "",
		"Print the Enterprise CRDs the operator has bundled then exit. Possible values: all, <crd prefix>. If a value other than 'all' is specified, the first CRD with a prefix of the specified value will be printed.")
	flag.BoolVar(&sgSetup, "aws-sg-setup", false,
		"Setup Security Groups in AWS (should only be used on OpenShift).")
	flag.BoolVar(&manageCRDs, "manage-crds", false,
		"Operator should manage the projectcalico.org and operator.tigera.io CRDs.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.WriteTo(os.Stdout), zap.UseFlagOptions(&opts)))

	if showVersion {
		// If the following line is updated then it might be necessary to update the release-verify target in the Makefile
		fmt.Println("Operator:", version.VERSION)
		fmt.Println("Calico:", components.CalicoRelease)
		fmt.Println("Enterprise:", components.EnterpriseRelease)
		os.Exit(0)
	}
	if printImages != "" {
		if strings.ToLower(printImages) == "list" {
			cmpnts := components.CalicoImages
			cmpnts = append(cmpnts, components.EnterpriseImages...)
			cmpnts = append(cmpnts, components.CommonImages...)

			for _, x := range cmpnts {
				ref, _ := components.GetReference(x, "", "", "", nil)
				fmt.Println(ref)
			}
			os.Exit(0)
		}
		fmt.Println("Invalid option for --print-images flag", printImages)
		os.Exit(1)
	}
	if printCalicoCRDs != "" {
		if err := showCRDs(operatorv1.Calico, printCalicoCRDs); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if printEnterpriseCRDs != "" {
		if err := showCRDs(operatorv1.TigeraSecureEnterprise, printEnterpriseCRDs); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
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

	cfg, err := config.GetConfig()
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	c, err := client.New(cfg, client.Options{})
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	policySelector, err := labels.Parse(fmt.Sprintf("projectcalico.org/tier == %s", networkpolicy.TigeraComponentTierName))
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	// Because we only run this as a job that is set up by the operator, it should not be
	// launched except by an operator that is the active operator. So we do not need to
	// check that we're the active operator before running the AWS SG setup.
	if sgSetup {
		log.Info("Setting up AWS Security Groups")

		err = awssgsetup.SetupAWSSecurityGroups(ctx, c)
		if err != nil {
			log.Error(err, "")
			os.Exit(1)
		}
		os.Exit(0)
	}

	sigHandler := ctrl.SetupSignalHandler()
	active.WaitUntilActive(cs, c, sigHandler, setupLog)
	log.Info("Active operator: proceeding")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr(),
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "operator-lock",
		// We should test this again in the future to see if the problem with LicenseKey updates
		// being missed is resolved. Prior to controller-runtime 0.7 we observed Test failures
		// where LicenseKey updates would be missed and the client cache did not have the LicenseKey.
		// The controller-runtime was updated and we made use of this ClientDisableCacheFor feature
		// for the LicenseKey. We should test again in the future to see if the cache issue is fixed
		// and we can remove this. Here is a link to the upstream issue
		// https://github.com/kubernetes-sigs/controller-runtime/issues/1316
		ClientDisableCacheFor: []client.Object{
			&v3.LicenseKey{},
		},
		// NetworkPolicy is served through the Tigera API Server, which currently restricts List and Watch
		// operations on NetworkPolicy to a single tier only, specified via label or field selector. If no
		// selector is specified, List and Watch return policies from the 'default' tier. The manager cache
		// must therefore apply a selector to specify the tier that the operator currently reconciles policy
		// within so that it can receive the expected resources for List and Watch. If the operator needs to
		// reconcile policy within multiple tiers, the API Server should be updated to serve policy from all
		// tiers that the user is authorized for.
		NewCache: cache.BuilderWithOptions(cache.Options{
			SelectorsByObject: cache.SelectorsByObject{
				&v3.NetworkPolicy{}:       {Label: policySelector},
				&v3.GlobalNetworkPolicy{}: {Label: policySelector},
			},
		}),
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

	// Determine if we're running in single or multi-tenant mode.
	multiTenant, err := utils.MultiTenant(ctx, clientset)
	if err != nil {
		log.Error(err, "Failed to discovery tenancy mode")
		os.Exit(1)
	}
	setupLog.WithValues("tenancy", multiTenant).Info("Checking tenancy mode")

	// Determine if PodSecurityPolicies are supported. PSPs were removed in
	// Kubernetes v1.25. We can remove this check once the operator not longer
	// supports Kubernetes < v1.25.0.
	// Skip installation of PSPs in OpenShift since we use Security Context
	// Constraints (SCC) instead.
	usePSP := false
	if provider != operatorv1.ProviderOpenShift {
		usePSP, err = utils.SupportsPodSecurityPolicies(clientset)
		if err != nil {
			setupLog.Error(err, "Failed to discover PodSecurityPolicy availability")
			os.Exit(1)
		}
	}
	setupLog.WithValues("supported", usePSP).Info("Checking if PodSecurityPolicies are supported by the cluster")

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

	clusterDomain, err := dns.GetClusterDomain(dns.DefaultResolveConfPath)
	if err != nil {
		clusterDomain = dns.DefaultClusterDomain
		log.Error(err, fmt.Sprintf("Couldn't find the cluster domain from the resolv.conf, defaulting to %s", clusterDomain))
	}

	kubernetesVersion, err := common.GetKubernetesVersion(clientset)
	if err != nil {
		log.Error(err, "Unable to resolve Kubernetes version, defaulting to v1.18")
		kubernetesVersion = &common.VersionInfo{Major: 1, Minor: 18}
	}

	options := options.AddOptions{
		DetectedProvider:    provider,
		EnterpriseCRDExists: enterpriseCRDExists,
		UsePSP:              usePSP,
		AmazonCRDExists:     amazonCRDExists,
		ClusterDomain:       clusterDomain,
		KubernetesVersion:   kubernetesVersion,
		ManageCRDs:          manageCRDs,
		ShutdownContext:     sigHandler,
		MultiTenant:         multiTenant,
	}

	err = controllers.AddToManager(mgr, options)
	if err != nil {
		setupLog.Error(err, "unable to create controllers")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(sigHandler); err != nil {
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

func showCRDs(variant operatorv1.ProductVariant, outputType string) error {
	first := true
	for _, v := range crds.GetCRDs(variant) {
		if outputType != "all" {
			if !strings.HasPrefix(v.Name, outputType) {
				continue
			}
		}
		b, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("Failed to Marshal %s: %v", v.Name, err)
		}
		if !first {
			fmt.Println("---")
		}
		first = false

		fmt.Printf("# %s\n", v.Name)
		fmt.Println(string(b))
	}
	// Indicates nothing was printed so we couldn't find the requested outputType
	if first {
		return fmt.Errorf("No CRD matching %s", outputType)
	}

	return nil
}
