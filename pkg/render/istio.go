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
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	renderistio "github.com/tigera/operator/pkg/render/istio"
)

type IstioConfig struct {
	Installation   *operatorv1.InstallationSpec
	Istio          *operatorv1.Istio
	IstioNamespace string
	Resources      *renderistio.IstioResources
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
	IstioReleaseName            = "tigera-istio"
	IstioIstiodDeploymentName   = "istiod"
	IstioCNIDaemonSetName       = "istio-cni-node"
	IstioZTunnelDaemonSetName   = "ztunnel"
	IstioOperatorAnnotationMode = "operator.tigera.io/istioAmbientMode"
	IstioOperatorAnnotationDSCP = "operator.tigera.io/istioDSCPMark"
	IstioFinalizer              = "operator.tigera.io/tigera-istio"
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

	compPilot := components.ComponentTigeraIstioPilot
	compCNI := components.ComponentTigeraIstioInstallCNI
	compZTunnel := components.ComponentTigeraIstioZTunnel
	compProxy := components.ComponentTigeraIstioProxyv2
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

	if overrides := c.cfg.Istio.Spec.Istiod; overrides != nil {
		rcomp.ApplyDeploymentOverrides(res.IstiodDeployment, overrides)
	}

	if overrides := c.cfg.Istio.Spec.IstioCNI; overrides != nil {
		rcomp.ApplyDaemonSetOverrides(res.CNIDaemonSet, overrides)
	}

	if overrides := c.cfg.Istio.Spec.ZTunnel; overrides != nil {
		rcomp.ApplyDaemonSetOverrides(res.ZTunnelDaemonSet, overrides)
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
			cont.Env = append(cont.Env, corev1.EnvVar{
				Name:  "MAGIC_DSCP_MARK",
				Value: strconv.FormatInt(int64(c.cfg.Istio.Spec.DSCPMark.ToUint8()), 10),
			})
		}
	}

	objs := []client.Object{}

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
