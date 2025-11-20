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
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	renderistio "github.com/tigera/operator/pkg/render/istio"
)

type IstioConfig struct {
	Installation   *operatorv1.InstallationSpec
	Istio          *operatorv1.Istio
	IstioNamespace string
	Resources      *renderistio.IstioResources
	PullSecrets    []*corev1.Secret
}

var _ Component = &IstioComponent{}

type IstioComponent struct {
	cfg                  *IstioConfig
	IstioPilotImage      string
	IstioInstallCNIImage string
	IstioZtunnelImage    string
	IstioProxyv2Image    string
}

const (
	IstioNamespace              = common.CalicoNamespace
	IstioReleaseName            = "calico-istio"
	IstioIstiodDeploymentName   = "istiod"
	IstioCNIDaemonSetName       = "istio-cni-node"
	IstioZTunnelDaemonSetName   = "ztunnel"
	IstioOperatorAnnotationMode = "operator.tigera.io/istioMode"
	IstioOperatorAnnotationDSCP = "operator.tigera.io/istioDSCPMark"
)

func NewIstioComponent(cfg *IstioConfig) *IstioComponent {
	return &IstioComponent{
		cfg: cfg,
	}
}

func (c *IstioComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	compPilot := components.ComponentCalicoIstioPilot
	compCNI := components.ComponentCalicoIstioInstallCNI
	compZTunnel := components.ComponentCalicoIstioZTunnel
	compProxy := components.ComponentCalicoIstioProxyv2
	if c.cfg.Installation.Variant == operatorv1.TigeraSecureEnterprise {
		compPilot = components.ComponentTigeraIstioPilot
		compCNI = components.ComponentTigeraIstioInstallCNI
		compZTunnel = components.ComponentTigeraIstioZTunnel
		compProxy = components.ComponentTigeraIstioProxyv2
	}
	c.IstioPilotImage, err = components.GetReference(compPilot, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}
	c.IstioInstallCNIImage, err = components.GetReference(compCNI, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}
	c.IstioZtunnelImage, err = components.GetReference(compZTunnel, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}
	c.IstioProxyv2Image, err = components.GetReference(compProxy, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) > 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}

	return nil
}

// Objects implements the Component interface.
func (c *IstioComponent) Objects() ([]client.Object, []client.Object) {
	res := c.cfg.Resources
	if c.cfg.Istio.Spec.Istiod != nil {
		if c.cfg.Istio.Spec.Istiod.Spec != nil && c.cfg.Istio.Spec.Istiod.Spec.Template != nil &&
			c.cfg.Istio.Spec.Istiod.Spec.Template.Spec != nil {
			if c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Affinity != nil {
				res.IstiodDeployment.Spec.Template.Spec.Affinity = c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Affinity
			}
			if c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.NodeSelector != nil {
				res.IstiodDeployment.Spec.Template.Spec.NodeSelector = c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.NodeSelector
			}
			if c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Resources != nil {
				res.IstiodDeployment.Spec.Template.Spec.Containers[0].Resources = *c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Resources
			}
			if len(c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Tolerations) > 0 {
				res.IstiodDeployment.Spec.Template.Spec.Tolerations = c.cfg.Istio.Spec.Istiod.Spec.Template.Spec.Tolerations
			}
		}
	}

	if c.cfg.Istio.Spec.IstioCNI != nil {
		if c.cfg.Istio.Spec.IstioCNI.Spec != nil && c.cfg.Istio.Spec.IstioCNI.Spec.Template != nil &&
			c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec != nil {
			if c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Affinity != nil {
				res.CNIDaemonSet.Spec.Template.Spec.Affinity = c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Affinity
			}
			if c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.NodeSelector != nil {
				res.CNIDaemonSet.Spec.Template.Spec.NodeSelector = c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.NodeSelector
			}
			if c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Resources != nil {
				res.CNIDaemonSet.Spec.Template.Spec.Containers[0].Resources = *c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Resources
			}
			if len(c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Tolerations) > 0 {
				res.CNIDaemonSet.Spec.Template.Spec.Tolerations = c.cfg.Istio.Spec.IstioCNI.Spec.Template.Spec.Tolerations
			}
		}
	}

	if c.cfg.Istio.Spec.ZTunnel != nil {
		if c.cfg.Istio.Spec.ZTunnel.Spec != nil && c.cfg.Istio.Spec.ZTunnel.Spec.Template != nil &&
			c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec != nil {
			if c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Affinity != nil {
				res.ZTunnelDaemonSet.Spec.Template.Spec.Affinity = c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Affinity
			}
			if c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.NodeSelector != nil {
				res.ZTunnelDaemonSet.Spec.Template.Spec.NodeSelector = c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.NodeSelector
			}
			if c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Resources != nil {
				res.ZTunnelDaemonSet.Spec.Template.Spec.Containers[0].Resources = *c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Resources
			}
			if len(c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Tolerations) > 0 {
				res.ZTunnelDaemonSet.Spec.Template.Spec.Tolerations = c.cfg.Istio.Spec.ZTunnel.Spec.Template.Spec.Tolerations
			}
		}
	}

	// Set required configs
	for i := range res.ZTunnelDaemonSet.Spec.Template.Spec.Containers {
		cont := &res.ZTunnelDaemonSet.Spec.Template.Spec.Containers[i]
		if cont.Name == "istio-proxy" {
			cont.Env = append(cont.Env, corev1.EnvVar{
				Name:  "TRANSPARENT_NETWORK_POLICIES",
				Value: "true",
			})
			break
		}
	}
	for i := range res.CNIDaemonSet.Spec.Template.Spec.Containers {
		cont := &res.CNIDaemonSet.Spec.Template.Spec.Containers[i]
		if cont.Name == "install-cni" {
			dscpValue := "23" // default value
			if c.cfg.Istio.Spec.DSCPMark != nil {
				dscpValue = strconv.FormatInt(int64(c.cfg.Istio.Spec.DSCPMark.ToUint8()), 10)
			}
			cont.Env = append(cont.Env, corev1.EnvVar{
				Name:  "MAGIC_DSCP_MARK",
				Value: dscpValue,
			})
		}
	}
	res.IstiodDeployment.Spec.Template.Spec.ImagePullSecrets = append(
		res.IstiodDeployment.Spec.Template.Spec.ImagePullSecrets,
		corev1.LocalObjectReference{Name: "tigera-pull-secret"},
	)
	res.CNIDaemonSet.Spec.Template.Spec.ImagePullSecrets = append(
		res.CNIDaemonSet.Spec.Template.Spec.ImagePullSecrets,
		corev1.LocalObjectReference{Name: "tigera-pull-secret"},
	)
	res.ZTunnelDaemonSet.Spec.Template.Spec.ImagePullSecrets = append(
		res.ZTunnelDaemonSet.Spec.Template.Spec.ImagePullSecrets,
		corev1.LocalObjectReference{Name: "tigera-pull-secret"},
	)

	// Tigera Istio Namespace
	objs := make([]client.Object, 0, len(res.Base)+len(res.Istiod)+
		len(res.CNI)+len(res.ZTunnel))

	// Append Istio resources in order: Base, Istiod, CNI, ZTunnel
	objs = append(objs, res.Base...)
	objs = append(objs, res.Istiod...)
	objs = append(objs, res.CNI...)
	objs = append(objs, res.ZTunnel...)

	return objs, nil
}

func (c *IstioComponent) Ready() bool {
	return true
}

func (c *IstioComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}
