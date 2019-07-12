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

package installation

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/intstr"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
)

const (
	defaultCNIImageName        = "calico/cni"
	defaultCalicoNodeImageName = "calico/node"
	defaultTigeraNodeImageName = "tigera/cnx-node"

	defaultCalicoKubeControllersImageName = "calico/kube-controllers"
	defaultTigeraKubeControllersImageName = "tigera/kube-controllers"

	defaultAPIServerImageName = "tigera/cnx-apiserver"
	defaultTigeraRegistry     = "quay.io/"

	defaultComplianceControllerImage  = "tigera/compliance-controller"
	defaultComplianceReporterImage    = "tigera/compliance-reporter"
	defaultComplianceServerImage      = "tigera/compliance-server"
	defaultComplianceSnapshotterImage = "tigera/compliance-snapshotter"
	defaultComplianceBenchmarkerImage = "tigera/compliance-benchmarker"

	defaultIntrusionDetectionControllerImageName   = "tigera/intrusion-detection-controller"
	defaultIntrusionDetectionJobInstallerImageName = "tigera/intrusion-detection-job-installer"
)

// fillDefaults fills in the default values for an instance.
func fillDefaults(instance *operator.Installation) {
	if len(instance.Spec.Version) == 0 {
		instance.Spec.Version = "latest"
	}
	if len(instance.Spec.Datastore.Type) == 0 {
		instance.Spec.Datastore.Type = operator.Kubernetes
	}
	if len(instance.Spec.Registry) == 0 {
		instance.Spec.Registry = "docker.io/"
		if instance.Spec.Variant == operator.TigeraSecureEnterprise {
			instance.Spec.Registry = defaultTigeraRegistry
		}
	}
	if !strings.HasSuffix(instance.Spec.Registry, "/") {
		instance.Spec.Registry = fmt.Sprintf("%s/", instance.Spec.Registry)
	}
	if len(instance.Spec.Variant) == 0 {
		instance.Spec.Variant = operator.Calico
	}
	if len(instance.Spec.CNINetDir) == 0 {
		instance.Spec.CNINetDir = "/etc/cni/net.d"
	}
	if len(instance.Spec.CNIBinDir) == 0 {
		instance.Spec.CNIBinDir = "/opt/cni/bin"
	}
	if len(instance.Spec.IPPools) == 0 {
		instance.Spec.IPPools = []operator.IPPool{
			{CIDR: "192.168.0.0/16"},
		}
	}
	if instance.Spec.Components.KubeProxy.Required {
		if len(instance.Spec.Components.KubeProxy.Image) == 0 {
			// Openshift's latest release uses Kubernetes 1.13. This is the latest stable kube-proxy version under that
			// release as of 5.21.19.
			instance.Spec.Components.KubeProxy.Image = "k8s.gcr.io/kube-proxy:v1.13.6"
		}
		if len(instance.Spec.Components.KubeProxy.APIServer) == 0 {
			// Default to using the injected environment variables. If configured with the --url-only-kubeconfig, these will be set
			// to the correct values based on the provided kubeconfig file.
			instance.Spec.Components.KubeProxy.APIServer = fmt.Sprintf("https://%s:%s", os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"))
		}
	}
	if instance.Spec.Components.Node.MaxUnavailable == nil {
		mu := intstr.FromInt(1)
		instance.Spec.Components.Node.MaxUnavailable = &mu
	}

	if len(instance.Spec.Components.Node.Image) == 0 {
		instance.Spec.Components.Node.Image = getImageName(instance, defaultCalicoNodeImageName, defaultTigeraNodeImageName)
	}
	if len(instance.Spec.Components.CNI.Image) == 0 {
		// CNI uses calico/CNI image for both Calico and TigeraSecureEnterprise.
		instance.Spec.Components.CNI.Image = getImageName(instance, defaultCNIImageName, defaultCNIImageName)
	}
	if len(instance.Spec.Components.KubeControllers.Image) == 0 {
		instance.Spec.Components.KubeControllers.Image = getImageName(instance, defaultCalicoKubeControllersImageName, defaultTigeraKubeControllersImageName)
	}
	if instance.Spec.Variant == operator.TigeraSecureEnterprise {
		if len(instance.Spec.Components.APIServer.Image) == 0 {
			instance.Spec.Components.APIServer.Image = getImageName(instance, "", defaultAPIServerImageName)
		}
		if len(instance.Spec.Components.Compliance.Controller.Image) == 0 {
			instance.Spec.Components.Compliance.Controller.Image = getImageName(instance, "",
				defaultComplianceControllerImage)
		}
		if len(instance.Spec.Components.Compliance.Reporter.Image) == 0 {
			instance.Spec.Components.Compliance.Reporter.Image = getImageName(instance, "",
				defaultComplianceReporterImage)
		}
		if len(instance.Spec.Components.Compliance.Server.Image) == 0 {
			instance.Spec.Components.Compliance.Server.Image = getImageName(instance, "",
				defaultComplianceServerImage)
		}
		if len(instance.Spec.Components.Compliance.Snapshotter.Image) == 0 {
			instance.Spec.Components.Compliance.Snapshotter.Image = getImageName(instance, "",
				defaultComplianceSnapshotterImage)
		}
		if len(instance.Spec.Components.Compliance.Benchmarker.Image) == 0 {
			instance.Spec.Components.Compliance.Benchmarker.Image = getImageName(instance, "",
				defaultComplianceBenchmarkerImage)
		}
		if len(instance.Spec.Components.IntrusionDetection.Controller.Image) == 0 {
			instance.Spec.Components.IntrusionDetection.Controller.Image = getImageName(instance, "", defaultIntrusionDetectionControllerImageName)
		}
		if len(instance.Spec.Components.IntrusionDetection.Installer.Image) == 0 {
			instance.Spec.Components.IntrusionDetection.Installer.Image = getImageName(instance, "", defaultIntrusionDetectionJobInstallerImageName)
		}
		if len(instance.Spec.Components.IntrusionDetection.Enabled) == 0 {
			instance.Spec.Components.IntrusionDetection.Enabled = operator.ComponentInstallEnabled
		}
	}
}

func getImageName(cr *operator.Installation, defaultCalicoImage, defaultTigeraImage string) string {
	imageName := defaultCalicoImage
	if cr.Spec.Variant == operator.TigeraSecureEnterprise {
		imageName = defaultTigeraImage
	}
	return fmt.Sprintf("%s%s:%s", cr.Spec.Registry, imageName, cr.Spec.Version)
}
