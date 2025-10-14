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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	renderistio "github.com/tigera/operator/pkg/render/istio"
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
		// XXX "image": c.istioPilotImage,
		"global": map[string]interface{}{
			"istioNamespace":         c.cfg.IstioNamespace,
			"operatorManageWebhooks": true,
			/* XXX
			"proxy": map[string]interface{}{
				"image": c.istioProxyv2Image,
			},
			"proxy_init": map[string]interface{}{
				"image": c.istioProxyv2Image,
			},
			*/
		},
		"profile": "ambient",
	}
	cniOpts := map[string]interface{}{
		// XXX "image": c.istioInstallCNIImage,
		"global": map[string]interface{}{
			"istioNamespace": c.cfg.IstioNamespace,
		},
		"profile": "ambient",
	}
	if c.cfg.Installation.KubernetesProvider == operatorv1.ProviderGKE {
		cniOpts["global"].(map[string]interface{})["platform"] = "gke"
	}
	ztunnelOpts := map[string]interface{}{
		//"image": c.istioZtunnelImage,
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

	// Append allow-tigera GlobalNetworkPolicies
	objs = append(objs, c.ztunnelAllowTigeraPolicies()...)

	return objs, nil
}

func (c *istioComponent) Ready() bool {
	return true
}

func (c *istioComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *istioComponent) ztunnelAllowTigeraPolicies() []client.Object {
	const (
		istioTier       = "allow-calico-istio"
		istioTierPrefix = istioTier + "."
		istioSelector   = "istio.io/dataplane-mode == 'ambient'"
	)
	istioPort := numorstring.SinglePort(15008)

	return []client.Object{
		&v3.Tier{
			TypeMeta: metav1.TypeMeta{Kind: "Tier", APIVersion: "projectcalico.org/v3"},
			ObjectMeta: metav1.ObjectMeta{
				Name: istioTier,
				Labels: map[string]string{
					"projectcalico.org/system-tier": "true",
				},
			},
			Spec: v3.TierSpec{
				Order:         ptr.To(float64(100.0)),
				DefaultAction: ptr.To(v3.Pass),
			},
		},
		&v3.GlobalNetworkPolicy{
			TypeMeta: metav1.TypeMeta{Kind: "GlobalNetworkPolicy", APIVersion: v3.SchemeGroupVersion.String()},
			ObjectMeta: metav1.ObjectMeta{
				Name: istioTierPrefix + "ambient-workloads",
			},
			Spec: v3.GlobalNetworkPolicySpec{
				Tier:     istioTier,
				Selector: istioSelector,
				Ingress: []v3.Rule{
					{
						Action:   v3.Allow,
						Protocol: &networkpolicy.TCPProtocol,
						Source: v3.EntityRule{
							Selector: istioSelector,
						},
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{istioPort},
						},
					},
					{
						Action:   v3.Allow,
						Protocol: &networkpolicy.TCPProtocol,
						Source: v3.EntityRule{
							NamespaceSelector: istioSelector,
						},
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{istioPort},
						},
					},
				},
				Egress: []v3.Rule{
					{
						Action:   v3.Allow,
						Protocol: &networkpolicy.TCPProtocol,
						Destination: v3.EntityRule{
							Selector: istioSelector,
							Ports:    []numorstring.Port{istioPort},
						},
					},
					{
						Action:   v3.Allow,
						Protocol: &networkpolicy.TCPProtocol,
						Destination: v3.EntityRule{
							NamespaceSelector: istioSelector,
							Ports:             []numorstring.Port{istioPort},
						},
					},
				},
				Types: []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			},
		},
		&v3.GlobalNetworkPolicy{
			TypeMeta: metav1.TypeMeta{Kind: "GlobalNetworkPolicy", APIVersion: v3.SchemeGroupVersion.String()},
			ObjectMeta: metav1.ObjectMeta{
				Name: istioTierPrefix + "ambient-namespaces",
			},
			Spec: v3.GlobalNetworkPolicySpec{
				Tier:              istioTier,
				NamespaceSelector: istioSelector,
				Ingress: []v3.Rule{
					{
						Action:   v3.Allow,
						Protocol: &networkpolicy.TCPProtocol,
						Source: v3.EntityRule{
							Selector: istioSelector,
						},
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{istioPort},
						},
					},
					{
						Action:   v3.Allow,
						Protocol: &networkpolicy.TCPProtocol,
						Source: v3.EntityRule{
							NamespaceSelector: istioSelector,
						},
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{istioPort},
						},
					},
				},
				Egress: []v3.Rule{
					{
						Action:   v3.Allow,
						Protocol: &networkpolicy.TCPProtocol,
						Destination: v3.EntityRule{
							Selector: istioSelector,
							Ports:    []numorstring.Port{istioPort},
						},
					},
					{
						Action:   v3.Allow,
						Protocol: &networkpolicy.TCPProtocol,
						Destination: v3.EntityRule{
							NamespaceSelector: istioSelector,
							Ports:             []numorstring.Port{istioPort},
						},
					},
				},
				Types: []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			},
		},
	}
}
