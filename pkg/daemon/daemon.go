// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

package daemon

import (
	"context"
	"fmt"
	"os"

	"github.com/operator-framework/operator-sdk/pkg/leader"
	"github.com/operator-framework/operator-sdk/pkg/restmapper"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/runtime/signals"
)

var (
	defaultMetricsPort int32 = 8484
	namespace                = ""
)

var log = logf.Log.WithName("daemon")

func Main() {
	// Try to get k8s api override from env and set the KUBERNETES_SERVICE_HOST/PORT if
	// kubeconfig is not specified. Kubeconfig has a precedence, but it unlikely to be set
	// in-cluster where we need the override to happen if there if the current setting
	// were to use a k8s service to acces k8s API, while the kube-proxy was disabled, e.g.
	// when about to switch to BPF dataplane.
	k8sHostOverride, k8sPortOverride, err := common.GetK8sEndpointOverride()
	if err != nil {
		if err := os.Setenv("KUBERNETES_SERVICE_HOST", k8sHostOverride); err != nil {
			log.Error(err, "Failed to set KUBERNETES_SERVICE_HOST from an override.")
			os.Exit(1)
		}
		if err := os.Setenv("KUBERNETES_SERVICE_PORT", k8sPortOverride); err != nil {
			log.Error(err, "Failed to set KUBERNETES_SERVICE_PORT from an override.")
			os.Exit(1)
		}
	}

	// Get a config to talk to the apiserver
	cfg, err := config.GetConfig()
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	ctx := context.Background()

	// Become the leader before proceeding
	err = leader.Become(ctx, "operator-lock")
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	// Create a new Cmd to provide shared dependencies and start components
	mgr, err := manager.New(cfg, manager.Options{
		Namespace:          namespace,
		MapperProvider:     restmapper.NewDynamicRESTMapper,
		MetricsBindAddress: metricsAddr(),
	})
	if err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	log.Info("Registering Components.")

	// Setup Scheme for all resources
	if err := apis.AddToScheme(mgr.GetScheme()); err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	// Attempt to auto discover the provider
	provider, err := utils.AutoDiscoverProvider(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Auto discovery of Provider failed")
		os.Exit(1)
	}
	log.WithValues("provider", provider).Info("Checking type of cluster")

	// Determine if we need to start the TSEE specific controllers.
	enterpriseCRDExists, err := utils.RequiresTigeraSecure(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to determine if TSEE is required")
		os.Exit(1)
	}
	log.WithValues("required", enterpriseCRDExists).Info("Checking if TSEE controllers are required")

	amazonCRDExists, err := utils.RequiresAmazonController(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to determine if AmazonCloudIntegration is required")
		os.Exit(1)
	}

	// Setup all Controllers
	if err := controller.AddToManager(mgr, options.AddOptions{
		DetectedProvider:    provider,
		EnterpriseCRDExists: enterpriseCRDExists,
		AmazonCRDExists:     amazonCRDExists,
	}); err != nil {
		log.Error(err, "")
		os.Exit(1)
	}

	log.Info("Starting the Cmd.")

	// Start the Cmd
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		log.Error(err, "Manager exited non-zero")
		os.Exit(1)
	}
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
