// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package render

import (
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	renderistio "github.com/tigera/operator/pkg/render/istio"
)

const (
	labelIstioAmbient        = "servicemesh.projectcalico.org/istio-dataplane"
	labelIstioAmbientEnabled = "ambient"
)

type IstioConfig struct {
	Installation     *operatorv1.InstallationSpec
	Istio            *operatorv1.Istio
	IstioNamespace   string
	IstioReleaseName string
}

type istioComponent struct {
	cfg                  *IstioConfig
	istioPilotImage      string
	istioInstallCNIImage string
	istioZtunnelImage    string
	istioProxyv2Image    string
}

const (
	IstioNamespace            = "calico-istio"
	IstioReleaseName          = "calico-istio"
	IstioIstiodDeploymentName = "istiod"
	IstioCNIDaemonSetName     = "istio-cni-node"
	IstioZTunnelDaemonSetName = "ztunnel"
)

func IstioComponent(cfg *IstioConfig) Component {
	return &istioComponent{
		cfg: cfg,
	}
}

func (c *istioComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	c.istioPilotImage, err = components.GetReference(components.ComponentIstioPilot, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}
	c.istioInstallCNIImage, err = components.GetReference(components.ComponentIstioInstallCNI, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}
	c.istioZtunnelImage, err = components.GetReference(components.ComponentIstioZTunnel, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}
	c.istioProxyv2Image, err = components.GetReference(components.ComponentIstioProxyv2, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) > 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}

	return nil
}

// Objects implements the Component interface.
func (c *istioComponent) Objects() ([]client.Object, []client.Object) {
	// Produce Helm templates for Istio
	baseOpts := map[string]interface{}{
		"global": map[string]interface{}{
			"istioNamespace": c.cfg.IstioNamespace,
		},
	}
	istiodOpts := map[string]interface{}{
		"image": c.istioPilotImage,
		"global": map[string]interface{}{
			"istioNamespace":         c.cfg.IstioNamespace,
			"operatorManageWebhooks": true,
			"proxy": map[string]interface{}{
				"image": c.istioProxyv2Image,
			},
			"proxy_init": map[string]interface{}{
				"image": c.istioProxyv2Image,
			},
		},
		"profile": "ambient",
	}
	cniOpts := map[string]interface{}{
		"image": c.istioInstallCNIImage,
		"global": map[string]interface{}{
			"istioNamespace": c.cfg.IstioNamespace,
		},
		"profile": "ambient",
		"ambient": map[string]interface{}{
			"enabled": true,
			"enablementSelectors": []interface{}{
				map[string]interface{}{
					"podSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
							labelIstioAmbient: labelIstioAmbientEnabled,
						},
					},
				},
				map[string]interface{}{
					"podSelector": map[string]interface{}{
						"matchExpression": []interface{}{
							map[string]interface{}{
								"key":      labelIstioAmbient,
								"operator": "NotIn",
								"values":   []interface{}{"none"},
							},
						},
					},
					"namespaceSelector": map[string]interface{}{
						"matchLabels": map[string]interface{}{
							labelIstioAmbient: labelIstioAmbientEnabled,
						},
					},
				},
			},
		},
	}
	if c.cfg.Installation.KubernetesProvider == operatorv1.ProviderGKE {
		cniOpts["global"].(map[string]interface{})["platform"] = "gke"
	}
	ztunnelOpts := map[string]interface{}{
		"image": c.istioZtunnelImage,
		"global": map[string]interface{}{
			"istioNamespace": c.cfg.IstioNamespace,
		},
	}
	resources, err := renderistio.GetResources(c.cfg.IstioNamespace, c.cfg.IstioReleaseName, baseOpts,
		istiodOpts, cniOpts, ztunnelOpts)
	if err != nil {
		return []client.Object{NewErrorObject(err)}, nil
	}

	if c.cfg.Istio.Spec.Istiod != nil {
		if c.cfg.Istio.Spec.Istiod.Spec != nil && c.cfg.Istio.Spec.Istiod.Spec.Template != nil &&
			c.cfg.Istio.Spec.Istiod.Spec.Template.Spec != nil {
			if c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Affinity != nil {
				resources.IstiodDeployment.Spec.Template.Spec.Affinity = c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Affinity
			}
			if c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.NodeSelector != nil {
				resources.IstiodDeployment.Spec.Template.Spec.NodeSelector = c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.NodeSelector
			}
			if c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Resources != nil {
				resources.IstiodDeployment.Spec.Template.Spec.Containers[0].Resources = *c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Resources
			}
			if len(c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Tolerations) > 0 {
				resources.IstiodDeployment.Spec.Template.Spec.Tolerations = c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Tolerations
			}
		}
	}

	if c.cfg.Istio.Spec.IstioCNI != nil {
		if c.cfg.Istio.Spec.IstioCNI.Spec != nil && c.cfg.Istio.Spec.IstioCNI.Spec.Template != nil &&
			c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec != nil {
			if c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Affinity != nil {
				resources.CNIDaemonSet.Spec.Template.Spec.Affinity = c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Affinity
			}
			if c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.NodeSelector != nil {
				resources.CNIDaemonSet.Spec.Template.Spec.NodeSelector = c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.NodeSelector
			}
			if c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Resources != nil {
				resources.CNIDaemonSet.Spec.Template.Spec.Containers[0].Resources = *c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Resources
			}
			if len(c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Tolerations) > 0 {
				resources.CNIDaemonSet.Spec.Template.Spec.Tolerations = c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Tolerations
			}
		}
	}

	if c.cfg.Istio.Spec.ZTunnel != nil {
		if c.cfg.Istio.Spec.ZTunnel.Spec != nil && c.cfg.Istio.Spec.ZTunnel.Spec.Template != nil &&
			c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec != nil {
			if c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Affinity != nil {
				resources.ZTunnelDaemonSet.Spec.Template.Spec.Affinity = c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Affinity
			}
			if c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.NodeSelector != nil {
				resources.ZTunnelDaemonSet.Spec.Template.Spec.NodeSelector = c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.NodeSelector
			}
			if c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Resources != nil {
				resources.ZTunnelDaemonSet.Spec.Template.Spec.Containers[0].Resources = *c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Resources
			}
			if len(c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Tolerations) > 0 {
				resources.ZTunnelDaemonSet.Spec.Template.Spec.Tolerations = c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Tolerations
			}
		}
	}

	// Set required configs
	for i := range resources.ZTunnelDaemonSet.Spec.Template.Spec.Containers {
		cont := &resources.ZTunnelDaemonSet.Spec.Template.Spec.Containers[i]
		if cont.Name == "istio-proxy" {
			cont.Env = append(cont.Env, v1.EnvVar{
				Name:  "TRANSPARENT_NETWORK_POLICIES",
				Value: "true",
			})
			break
		}
	}

	// Tigera Istio Namespace
	objs := make([]client.Object, 0, len(resources.Base)+len(resources.Istiod)+
		len(resources.CNI)+len(resources.ZTunnel)+1)

	// Append Namespace
	objs = append(objs, CreateNamespace(
		c.cfg.IstioNamespace,
		c.cfg.Installation.KubernetesProvider,
		PSSPrivileged, // Needed for HostPath volume to write logs to
		c.cfg.Installation.Azure,
	))

	// Append Istio resources in order: Base, Istiod, CNI, ZTunnel
	objs = append(objs, resources.Base...)
	objs = append(objs, resources.Istiod...)
	objs = append(objs, resources.CNI...)
	objs = append(objs, resources.ZTunnel...)

	return objs, nil
}

func (c *istioComponent) Ready() bool {
	return true
}

func (c *istioComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}
