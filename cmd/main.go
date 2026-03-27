// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/url"
	"os"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/log"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/tigera/operator/internal/controller"
	"github.com/tigera/operator/pkg/active"
	"github.com/tigera/operator/pkg/apigroup"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/awssgsetup"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/metrics"
	"github.com/tigera/operator/pkg/controller/migration/datastoremigration"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/imports/admission"
	"github.com/tigera/operator/pkg/imports/crds"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/intrusiondetection/dpi"
	"github.com/tigera/operator/pkg/render/istio"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/render/logstorage/eck"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/version"

	operatortigeraiov1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/yaml"
	// +kubebuilder:scaffold:imports
)

var (
	defaultMetricsPort int32 = 9484
	scheme                   = runtime.NewScheme()
	setupLog                 = ctrl.Log.WithName("setup")
)

// bootstrapConfigMapName is the name of the ConfigMap that contains cluster-wide
// configuration for the operator loaded at startup.
const bootstrapConfigMapName = "operator-bootstrap-config"

func init() {
	// +kubebuilder:scaffold:scheme
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(apiextensions.AddToScheme(scheme))
	utilruntime.Must(operatortigeraiov1.AddToScheme(scheme))
	utilruntime.Must(datastoremigration.AddToScheme(scheme))
}

func printVersion() {
	log.Info(fmt.Sprintf("Version: %v", version.VERSION))
	log.Info(fmt.Sprintf("Go Version: %s", goruntime.Version()))
	log.Info(fmt.Sprintf("Go OS/Arch: %s/%s", goruntime.GOOS, goruntime.GOARCH))
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
	var preDelete bool
	var variant string

	// bootstrapCRDs is a flag that can be used to install the CRDs and exit. This is useful for
	// workflows that use an init container to install CustomResources prior to the operator starting.
	var bootstrapCRDs bool

	flag.BoolVar(
		&enableLeaderElection, "enable-leader-election", true,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.",
	)
	flag.StringVar(
		&printCalicoCRDs, "print-calico-crds", "",
		`Print the Calico CRDs the operator has bundled then exit. Possible values: all, <crd prefix>.
If a value other than 'all' is specified, the first CRD with a prefix of the specified value will be printed.`,
	)
	flag.StringVar(
		&printEnterpriseCRDs, "print-enterprise-crds", "",
		`Print the Enterprise CRDs the operator has bundled then exit. Possible values: all, <crd prefix>.
If a value other than 'all' is specified, the first CRD with a prefix of the specified value will be printed.`,
	)
	flag.StringVar(&urlOnlyKubeconfig, "url-only-kubeconfig", "", "Path to a kubeconfig, but only for the apiserver url.")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.StringVar(&printImages, "print-images", "", "Print the default images the operator could deploy and exit. Possible values: list")
	flag.BoolVar(&sgSetup, "aws-sg-setup", false, "Setup Security Groups in AWS (should only be used on OpenShift).")
	flag.BoolVar(&manageCRDs, "manage-crds", false, "Operator should manage the projectcalico.org and operator.tigera.io CRDs.")
	flag.BoolVar(&preDelete, "pre-delete", false, "Run helm pre-deletion hook logic, then exit.")
	flag.BoolVar(&bootstrapCRDs, "bootstrap-crds", false, "Install CRDs and exit")
	flag.StringVar(&variant, "variant", string(operatortigeraiov1.Calico), "Default product variant to assume during boostrapping.")

	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.WriteTo(os.Stdout), zap.UseFlagOptions(&opts)))

	if showVersion {
		// If the following line is updated then it might be necessary to update the assertOperatorImageVersion in hack/release/build.go
		fmt.Println("Operator:", version.VERSION)
		fmt.Println("Calico:", components.CalicoRelease)
		fmt.Println("Enterprise:", components.EnterpriseRelease)
		os.Exit(0)
	}

	if printImages != "" {
		var cmpnts []components.Component
		if strings.ToLower(printImages) == "list" {
			cmpnts = components.CalicoImages
			cmpnts = append(cmpnts, components.EnterpriseImages...)
		} else if strings.ToLower(printImages) == "listcalico" {
			cmpnts = components.CalicoImages
		} else if strings.ToLower(printImages) == "listenterprise" {
			cmpnts = components.EnterpriseImages
		} else {
			fmt.Println("Invalid option for --print-images flag", printImages)
			os.Exit(1)
		}
		cmpnts = append(cmpnts, components.ComponentOperatorInit)
		for _, x := range cmpnts {
			ref, _ := components.GetReference(x, "", "", "", nil)
			fmt.Println(ref)
		}
		os.Exit(0)
	}

	if printCalicoCRDs != "" {
		if err := showCRDs(operatortigeraiov1.Calico, printCalicoCRDs); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if printEnterpriseCRDs != "" {
		if err := showCRDs(operatortigeraiov1.TigeraSecureEnterprise, printEnterpriseCRDs); err != nil {
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

	ctx, cancel := context.WithCancel(context.Background())

	cfg, err := config.GetConfig()
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	v3CRDs, err := apis.UseV3CRDS(cfg)
	if err != nil {
		log.Error(err, "Failed to determine CRD version to use")
		os.Exit(1)
	}

	// Tell the component handler which API group to inject into workloads.
	if v3CRDs {
		apigroup.Set(apigroup.V3)
	}

	// Add the Calico API to the scheme, now that we know which backing CRD version to use.
	utilruntime.Must(apis.AddToScheme(scheme, v3CRDs))

	// Because we only run this as a job that is set up by the operator, it should not be
	// launched except by an operator that is the active operator. So we do not need to
	// check that we're the active operator before running the AWS SG setup.
	if sgSetup {
		log.Info("Setting up AWS Security Groups")

		err = awssgsetup.SetupAWSSecurityGroups(ctx, c, os.Getenv("HOSTED_OPENSHIFT") == "true")
		if err != nil {
			log.Error(err, "")
			os.Exit(1)
		}
		os.Exit(0)
	}

	if preDelete {
		// We've built a client - we can use it to clean up.
		if err := executePreDeleteHook(ctx, c); err != nil {
			log.Error(err, "Failed to complete pre-delete hook")
			os.Exit(1)
		}
		os.Exit(0)
	}

	// sigHandler is a context that is canceled when we receive a termination
	// signal. We don't want to immeditely terminate upon receipt of such a signal since
	// there may be cleanup required. So, we will pass a separate context to our controllers.
	// That context will be canceled after a successful cleanup.
	sigHandler := ctrl.SetupSignalHandler()
	active.WaitUntilActive(cs, c, sigHandler, setupLog)
	log.Info("Active operator: proceeding")

	metricsOpts := server.Options{
		BindAddress: metricsAddr(),
	}
	var certLoader *dynamicCertLoader
	if metricsTLSEnabled() {
		certLoader = newDynamicCertLoader()
		metricsOpts.SecureServing = true
		metricsOpts.TLSOpts = []func(*tls.Config){
			func(cfg *tls.Config) {
				cfg.GetCertificate = certLoader.GetCertificate
				cfg.ClientAuth = tls.RequireAndVerifyClientCert
				cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
					pool := certLoader.GetClientCAs()
					return &tls.Config{
						GetCertificate: certLoader.GetCertificate,
						ClientAuth:     tls.RequireAndVerifyClientCert,
						ClientCAs:      pool,
						MinVersion:     tls.VersionTLS12,
					}, nil
				}
				cfg.MinVersion = tls.VersionTLS12
			},
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsOpts,
		WebhookServer: webhook.NewServer(webhook.Options{
			Port: 9443,
		}),
		LeaderElection:   enableLeaderElection,
		LeaderElectionID: "operator-lock",
		// We should test this again in the future to see if the problem with LicenseKey updates
		// being missed is resolved. Prior to controller-runtime 0.7 we observed Test failures
		// where LicenseKey updates would be missed and the client cache did not have the LicenseKey.
		// The controller-runtime was updated and we made use of this ClientDisableCacheFor feature
		// for the LicenseKey. We should test again in the future to see if the cache issue is fixed
		// and we can remove this. Here is a link to the upstream issue
		// https://github.com/kubernetes-sigs/controller-runtime/issues/1316
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: []client.Object{
					&v3.LicenseKey{},
				},
			},
		},

		// Explicitly set the MapperProvider to the NewDynamicRESTMapper, as we had previously had issues with the default
		// not being this mapper (which has since been rectified). It was a tough issue to figure out when the default
		// had changed out from under us, so better to continue to explicitly set it as we know this is the mapper we want.
		MapperProvider: apiutil.NewDynamicRESTMapper,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// If configured to manage CRDs, do a preliminary install of them here. The Installation controller
	// will reconcile them as well, but we need to make sure they are installed before we start the rest of the controllers.
	if bootstrapCRDs || manageCRDs {
		setupLog.WithValues("v3", v3CRDs).Info("Ensuring CRDs are installed")

		if err := crds.Ensure(mgr.GetClient(), variant, v3CRDs, setupLog); err != nil {
			setupLog.Error(err, "Failed to ensure CRDs are created")
			os.Exit(1)
		}

		if err := admission.Ensure(mgr.GetClient(), variant, v3CRDs, setupLog); err != nil {
			setupLog.Error(err, "Failed to ensure MutatingAdmissionPolicies are created")
			os.Exit(1)
		}

		if bootstrapCRDs {
			setupLog.Info("CRDs installed successfully")
			os.Exit(0)
		}
	}

	// Start a goroutine to handle termination.
	go func() {
		// Cancel the main context when we are done.
		defer cancel()

		// Wait for a signal.
		<-sigHandler.Done()

		// Check if we need to do any cleanup.
		client := mgr.GetClient()
		instance := &operatortigeraiov1.Installation{}
		retries := 0
		for {
			if err := client.Get(ctx, utils.DefaultInstanceKey, instance); errors.IsNotFound(err) {
				// No installation - we can exit immediately.
				return
			} else if err != nil {
				// Error querying - retry after a small sleep.
				if retries >= 5 {
					log.Errorf("Too many retries, exiting with error: %s", err)
					return
				}
				log.Errorf("Error querying Installation, will retry: %s", err)
				retries++
				time.Sleep(1 * time.Second)
				continue
			}

			// Success
			break
		}

		if instance.DeletionTimestamp == nil {
			// Installation isn't terminating, so we can exit immediately.
			return
		}

		// We need to wait for termination to complete. We can do this by checking if the Installation
		// resource has been cleaned up or not.
		to := 60 * time.Second
		log.Infof("Waiting up to %s for graceful termination to complete", to)
		timeout := time.After(to)
		for {
			select {
			case <-timeout:
				// Timeout. Continue with shutdown.
				log.Warning("Timed out waiting for graceful shutdown to complete")
				return
			default:
				err := client.Get(ctx, utils.DefaultInstanceKey, instance)
				if errors.IsNotFound(err) {
					// Installation has been cleaned up, we can terminate.
					log.Info("Graceful termination complete")
					return
				} else if err != nil {
					log.Errorf("Error querying Installation: %s", err)
				}
				time.Sleep(1 * time.Second)
			}
		}
	}()

	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to get Kubernetes clientset")
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

	// Determine if we need to start the Enterprise specific controllers.
	enterpriseCRDExists, err := utils.RequiresTigeraSecure(clientset)
	if err != nil {
		setupLog.Error(err, "Failed to determine if Enterprise controllers are required")
		os.Exit(1)
	}
	setupLog.WithValues("required", enterpriseCRDExists).Info("Checking if Enterprise controllers are required")

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

	// The operator MUST not run within one of the Namespaces that it itself manages. Perform an early check here
	// to make sure that we're not doing so, and exit if we are.
	badNamespaces := []string{
		common.CalicoNamespace,
		"calico-apiserver",
		render.ElasticsearchNamespace,
		render.ComplianceNamespace,
		render.IntrusionDetectionNamespace,
		dpi.DeepPacketInspectionNamespace,
		eck.OperatorNamespace,
		render.LogCollectorNamespace,
		render.CSIDaemonSetNamespace,
		render.ManagerNamespace,
		istio.IstioNamespace,
	}
	for _, ns := range badNamespaces {
		if common.OperatorNamespace() == ns {
			log.Error("Operator must not be run within a Namespace managed by the operator, please select a different namespace")
			log.Error(fmt.Sprintf("The following namespaces cannot be used: %s", badNamespaces))
			os.Exit(1)
		}
	}

	// Laod the operator's bootstrap configmap, if it exists.
	bootConfig, err := clientset.CoreV1().ConfigMaps(common.OperatorNamespace()).Get(ctx, bootstrapConfigMapName, metav1.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			log.Error(err, "Failed to load bootstrap configmap")
			os.Exit(1)
		}
	}

	// Start a watch on our bootstrap configmap so we can restart if it changes.
	if err = utils.MonitorConfigMap(clientset, bootstrapConfigMapName, bootConfig.Data); err != nil {
		log.Error(err, "Failed to monitor bootstrap configmap")
		os.Exit(1)
	}

	options := options.ControllerOptions{
		DetectedProvider:    provider,
		EnterpriseCRDExists: enterpriseCRDExists,
		ClusterDomain:       clusterDomain,
		KubernetesVersion:   kubernetesVersion,
		ManageCRDs:          manageCRDs,
		ShutdownContext:     ctx,
		K8sClientset:        clientset,
		MultiTenant:         multiTenant,
		ElasticExternal:     utils.UseExternalElastic(bootConfig),
		UseV3CRDs:           v3CRDs,
	}

	// Before we start any controllers, make sure our options are valid.
	if err := verifyConfiguration(ctx, clientset, options); err != nil {
		setupLog.Error(err, "Invalid configuration")
		os.Exit(1)
	}

	err = controller.AddToManager(mgr, options)
	if err != nil {
		setupLog.Error(err, "unable to create controllers")
		os.Exit(1)
	}

	// Register custom Prometheus metrics collector.
	if metricsEnabled() {
		collector := metrics.NewOperatorCollector(mgr.GetClient())
		ctrlmetrics.Registry.MustRegister(collector)
	}

	// Start watching TLS secrets for the mTLS metrics endpoint.
	if certLoader != nil {
		go watchMetricsTLSSecrets(ctx, mgr, certLoader)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
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
	err = os.Setenv("KUBERNETES_SERVICE_HOST", url.Hostname())
	if err != nil {
		return err
	}
	err = os.Setenv("KUBERNETES_SERVICE_PORT", url.Port())
	if err != nil {
		return err
	}
	return nil
}

// metricsAddr returns the bind address for the metrics endpoint.
// When METRICS_ENABLED is not "true", returns "0" to disable metrics.
// Otherwise, defaults to 0.0.0.0:9484 and allows overriding via
// METRICS_HOST and METRICS_PORT.
func metricsAddr() string {
	if !metricsEnabled() {
		// the controller-runtime accepts '0' to denote that metrics should be disabled.
		return "0"
	}

	metricsHost := os.Getenv("METRICS_HOST")
	if metricsHost == "" {
		metricsHost = "0.0.0.0"
	}

	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		return fmt.Sprintf("%s:%d", metricsHost, defaultMetricsPort)
	}

	return fmt.Sprintf("%s:%s", metricsHost, metricsPort)
}

// metricsEnabled returns true when the operator metrics endpoint is enabled.
func metricsEnabled() bool {
	return strings.EqualFold(os.Getenv("METRICS_ENABLED"), "true")
}

func showCRDs(variant operatortigeraiov1.ProductVariant, outputType string) error {
	first := true
	for _, v := range crds.GetCRDs(variant, os.Getenv("CALICO_API_GROUP") == "projectcalico.org/v3") {
		if outputType != "all" {
			if !strings.HasPrefix(v.Name, outputType) {
				continue
			}
		}
		b, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to Marshal %s: %v", v.Name, err)
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
		return fmt.Errorf("no CRD matching %s", outputType)
	}

	return nil
}

func executePreDeleteHook(ctx context.Context, c client.Client) error {
	defer log.Info("preDelete hook exiting")

	// Clean up any custom-resources first - this will trigger teardown of pods deloyed
	// by the operator, and give the operator a chance to clean up gracefully.
	installation := &operatortigeraiov1.Installation{}
	installation.Name = utils.DefaultInstanceKey.Name
	apiserver := &operatortigeraiov1.APIServer{}
	apiserver.Name = utils.DefaultInstanceKey.Name
	whisker := &operatortigeraiov1.Whisker{}
	whisker.Name = utils.DefaultInstanceKey.Name
	goldmane := &operatortigeraiov1.Goldmane{}
	goldmane.Name = utils.DefaultInstanceKey.Name
	for _, o := range []client.Object{whisker, goldmane, installation, apiserver} {
		if err := c.Delete(ctx, o); err != nil {
			if errors.IsNotFound(err) {
				continue
			}
			return err
		}
	}

	// Wait for the Installation to be deleted.
	to := time.After(5 * time.Minute)
	for {
		select {
		case <-to:
			return fmt.Errorf("timeout waiting for pre-delete hook")
		default:
			if err := c.Get(ctx, utils.DefaultInstanceKey, installation); errors.IsNotFound(err) {
				// It's gone! We can return.
				return nil
			}
		}
		log.Info("Waiting for Installation to be fully deleted")
		time.Sleep(5 * time.Second)
	}
}

// verifyConfiguration verifies that the final configuration of the operator is correct before starting any controllers.
func verifyConfiguration(ctx context.Context, cs kubernetes.Interface, opts options.ControllerOptions) error {
	if opts.ElasticExternal {
		// There should not be an internal-es cert
		if _, err := cs.CoreV1().Secrets(render.ElasticsearchNamespace).Get(ctx, render.TigeraElasticsearchInternalCertSecret, metav1.GetOptions{}); err != nil {
			if errors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("unexpected error encountered when confirming elastic is not currently internal: %v", err)
		}
		return fmt.Errorf("refusing to run: configured as external ES but secret/%s found which suggests internal ES", render.TigeraElasticsearchInternalCertSecret)
	} else {
		// There should not be an external-es cert
		_, err := cs.CoreV1().Secrets(render.ElasticsearchNamespace).Get(ctx, logstorage.ExternalCertsSecret, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("unexpected error encountered when confirming elastic is not currently external: %v", err)
		}
		return fmt.Errorf("refusing to run: configured as internal-es but secret/%s found which suggests external ES", logstorage.ExternalCertsSecret)
	}
}

// metricsTLSEnabled returns true when the operator metrics endpoint should use mTLS.
func metricsTLSEnabled() bool {
	return strings.EqualFold(os.Getenv("METRICS_SCHEME"), "https")
}

// dynamicCertLoader dynamically loads TLS certificates from Kubernetes secrets
// for the metrics endpoint. The monitor controller creates the server cert, and
// the client CA is loaded from the Prometheus client TLS secret.
type dynamicCertLoader struct {
	mu       sync.RWMutex
	cert     *tls.Certificate
	clientCA *x509.CertPool
}

func newDynamicCertLoader() *dynamicCertLoader {
	return &dynamicCertLoader{
		clientCA: x509.NewCertPool(),
	}
}

// GetCertificate returns the current server certificate for the metrics endpoint.
func (d *dynamicCertLoader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.cert == nil {
		return nil, fmt.Errorf("operator metrics TLS certificate not yet available")
	}
	return d.cert, nil
}

// GetClientCAs returns the current client CA pool.
func (d *dynamicCertLoader) GetClientCAs() *x509.CertPool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.clientCA
}

// updateServerCert updates the server certificate from a Kubernetes TLS secret.
func (d *dynamicCertLoader) updateServerCert(secret *corev1.Secret) error {
	certPEM, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return fmt.Errorf("secret %s/%s missing %s", secret.Namespace, secret.Name, corev1.TLSCertKey)
	}
	keyPEM, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return fmt.Errorf("secret %s/%s missing %s", secret.Namespace, secret.Name, corev1.TLSPrivateKeyKey)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse TLS keypair from %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cert = &cert
	return nil
}

// updateClientCA updates the client CA pool from a Kubernetes secret containing a certificate.
func (d *dynamicCertLoader) updateClientCA(secrets ...*corev1.Secret) {
	pool := x509.NewCertPool()
	for _, s := range secrets {
		if s == nil {
			continue
		}
		if certPEM, ok := s.Data[corev1.TLSCertKey]; ok {
			pool.AppendCertsFromPEM(certPEM)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.clientCA = pool
}

// watchMetricsTLSSecrets periodically loads TLS secrets for the metrics endpoint.
// It runs until the context is canceled.
func watchMetricsTLSSecrets(ctx context.Context, mgr ctrl.Manager, loader *dynamicCertLoader) {
	logger := ctrl.Log.WithName("metrics-tls")

	// Wait for the cache to start before reading secrets.
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		logger.Error(fmt.Errorf("cache sync failed"), "Cannot watch metrics TLS secrets")
		return
	}

	c := mgr.GetClient()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	operatorNs := common.OperatorNamespace()

	serverCertLoaded := false
	loadSecrets := func() {
		// Load operator server TLS secret.
		serverSecret := &corev1.Secret{}
		if err := c.Get(ctx, types.NamespacedName{Name: monitor.OperatorMetricsSecretName, Namespace: operatorNs}, serverSecret); err != nil {
			if !serverCertLoaded {
				logger.Info("Metrics mTLS is enabled but the server certificate secret is not yet available. "+
					"Create the secret manually or apply the Monitor CR to have it provisioned automatically.",
					"secret", monitor.OperatorMetricsSecretName, "namespace", operatorNs)
			} else {
				logger.V(2).Info("Operator metrics TLS secret not yet available", "error", err)
			}
		} else {
			if err := loader.updateServerCert(serverSecret); err != nil {
				logger.Error(err, "Failed to update operator metrics server cert")
			} else {
				if !serverCertLoaded {
					logger.Info("Operator metrics TLS certificate loaded successfully", "secret", monitor.OperatorMetricsSecretName)
				}
				serverCertLoaded = true
			}
		}

		// Load client CA from the tigera-ca-private secret. Any cert signed by this CA
		// will be trusted for mTLS client authentication.
		caSecret := &corev1.Secret{}
		if err := c.Get(ctx, types.NamespacedName{Name: certificatemanagement.CASecretName, Namespace: operatorNs}, caSecret); err == nil {
			loader.updateClientCA(caSecret)
		}
	}

	// Initial load.
	loadSecrets()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			loadSecrets()
		}
	}
}
