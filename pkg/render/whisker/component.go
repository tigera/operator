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

package whisker

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	rcomp "github.com/tigera/operator/pkg/render/common/components"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/common/selector"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// The names of the components related to the Guardian related rendered objects.
const (
	WhiskerName               = "whisker"
	WhiskerNamespace          = common.CalicoNamespace
	WhiskerServiceAccountName = WhiskerName
	WhiskerDeploymentName     = WhiskerName

	WhiskerContainerName        = "whisker"
	WhiskerBackendContainerName = "whisker-backend"

	WhiskerBackendKeyPairSecret = "whisker-backend-key-pair"
	GoldmaneDeploymentName      = "goldmane"
	GoldmaneServicePort         = 7443
	GoldmaneNamespace           = common.CalicoNamespace
)

func Whisker(cfg *Configuration) render.Component {
	c := &Component{cfg: cfg}

	return c
}

// Configuration contains all the config information needed to render the component.
type Configuration struct {
	PullSecrets           []*corev1.Secret
	OpenShift             bool
	Installation          *operatorv1.InstallationSpec
	TrustedCertBundle     certificatemanagement.TrustedBundleRO
	WhiskerBackendKeyPair certificatemanagement.KeyPairInterface
	Whisker               *operatorv1.Whisker
	ClusterID             string
	CalicoVersion         string
	ClusterType           string
	ClusterDomain         string
}

type Component struct {
	cfg *Configuration

	whiskerImage        string
	whiskerBackendImage string
}

func (c *Component) ResolveImages(is *operatorv1.ImageSet) error {
	reg := c.cfg.Installation.Registry
	path := c.cfg.Installation.ImagePath
	prefix := c.cfg.Installation.ImagePrefix

	var err error

	c.whiskerImage, err = components.GetReference(components.ComponentCalicoWhisker, reg, path, prefix, is)
	if err != nil {
		return err
	}

	c.whiskerBackendImage, err = components.GetReference(components.ComponentCalicoWhiskerBackend, reg, path, prefix, is)
	if err != nil {
		return err
	}

	return nil
}

func (c *Component) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (c *Component) Objects() ([]client.Object, []client.Object) {
	deployment := c.deployment()
	if overrides := c.cfg.Whisker.Spec.WhiskerDeployment; overrides != nil {
		rcomp.ApplyDeploymentOverrides(deployment, overrides)
	}

	objs := []client.Object{
		c.serviceAccount(),
		deployment,
		c.whiskerService(),
		c.networkPolicy(),
	}

	objs = append(objs, secret.ToRuntimeObjects(secret.CopyToNamespace(WhiskerNamespace, c.cfg.PullSecrets...)...)...)

	// Whisker needs to be removed if the installation is not Calico, since it's not supported (yet!) for any other variant.
	if c.cfg.Installation.Variant == operatorv1.Calico {
		return objs, nil
	} else {
		return nil, objs
	}
}

func (c *Component) Ready() bool {
	return true
}

func (c *Component) serviceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta:   metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerServiceAccountName, Namespace: WhiskerNamespace},
	}
}

func (c *Component) whiskerContainer() corev1.Container {
	return corev1.Container{
		Name:            WhiskerContainerName,
		Image:           c.whiskerImage,
		ImagePullPolicy: render.ImagePullPolicy(),
		Env: []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "INFO"},
			{Name: "CALICO_VERSION", Value: c.cfg.CalicoVersion},
			{Name: "CLUSTER_ID", Value: c.cfg.ClusterID},
			{Name: "CLUSTER_TYPE", Value: c.cfg.ClusterType},
			{Name: "NOTIFICATIONS", Value: string(*c.cfg.Whisker.Spec.Notifications)},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
	}
}

func (c *Component) whiskerService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "whisker",
			Namespace: WhiskerNamespace,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 8081}},
			Selector: map[string]string{
				"k8s-app": WhiskerDeploymentName,
			},
		},
	}
}

func (c *Component) whiskerBackendContainer() corev1.Container {
	return corev1.Container{
		Name:            WhiskerBackendContainerName,
		Image:           c.whiskerBackendImage,
		ImagePullPolicy: render.ImagePullPolicy(),
		Env: []corev1.EnvVar{
			{Name: "LOG_LEVEL", Value: "INFO"},
			{Name: "PORT", Value: "3002"},
			{Name: "GOLDMANE_HOST", Value: fmt.Sprintf("goldmane.%s.svc.%s:7443", GoldmaneNamespace, c.cfg.ClusterDomain)},
			{Name: "TLS_CERT_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountCertificateFilePath()},
			{Name: "TLS_KEY_PATH", Value: c.cfg.WhiskerBackendKeyPair.VolumeMountKeyFilePath()},
		},
		SecurityContext: securitycontext.NewNonRootContext(),
		VolumeMounts: append(
			c.cfg.TrustedCertBundle.VolumeMounts(c.SupportedOSType()),
			c.cfg.WhiskerBackendKeyPair.VolumeMount(c.SupportedOSType())),
	}
}

func (c *Component) deployment() *appsv1.Deployment {
	tolerations := append(c.cfg.Installation.ControlPlaneTolerations, rmeta.TolerateCriticalAddonsAndControlPlane...)
	if c.cfg.Installation.KubernetesProvider.IsGKE() {
		tolerations = append(tolerations, rmeta.TolerateGKEARM64NoSchedule)
	}

	ctrs := []corev1.Container{c.whiskerContainer(), c.whiskerBackendContainer()}
	volumes := []corev1.Volume{c.cfg.TrustedCertBundle.Volume(), c.cfg.WhiskerBackendKeyPair.Volume()}

	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      WhiskerDeploymentName,
			Namespace: WhiskerNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.ToPtr(int32(1)),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: WhiskerDeploymentName,
				},
				Spec: corev1.PodSpec{
					NodeSelector:       c.cfg.Installation.ControlPlaneNodeSelector,
					ServiceAccountName: WhiskerServiceAccountName,
					Tolerations:        tolerations,
					ImagePullSecrets:   secret.GetReferenceList(c.cfg.PullSecrets),
					Containers:         ctrs,
					Volumes:            volumes,
				},
			},
		},
	}
}

func (c *Component) networkPolicy() *netv1.NetworkPolicy {
	egressRules := []netv1.NetworkPolicyEgressRule{
		{
			To: []netv1.NetworkPolicyPeer{
				{
					PodSelector: selector.PodLabelSelector(GoldmaneDeploymentName),
				},
			},
			Ports: []netv1.NetworkPolicyPort{{
				Protocol: ptr.ToPtr(corev1.ProtocolTCP),
				Port:     ptr.ToPtr(intstr.FromInt32(GoldmaneServicePort)),
			}},
		},
	}
	return &netv1.NetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: WhiskerName, Namespace: WhiskerNamespace},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
			PodSelector: *selector.PodLabelSelector(WhiskerDeploymentName),
			Egress:      append(egressRules, networkpolicy.K8sDNSEgressRules(c.cfg.OpenShift)...),
		},
	}
}
