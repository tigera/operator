// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

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

package render_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/tls"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Rendering tests for PacketCapture API component", func() {

	var secret certificatemanagement.KeyPairInterface
	var cli client.Client
	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain)
		Expect(err).NotTo(HaveOccurred())
		secret, err = certificateManager.GetOrCreateKeyPair(cli, render.PacketCaptureCertSecret, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())
	})

	// Pull secret
	var pullSecrets = []*corev1.Secret{{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pull-secret",
			Namespace: common.OperatorNamespace(),
		},
	}}
	// Installation with minimal setup
	var defaultInstallation = operatorv1.InstallationSpec{}

	// Rendering packet capture resources
	var renderPacketCapture = func(i operatorv1.InstallationSpec, config authentication.KeyValidatorConfig) (resources []client.Object) {
		cfg := &render.PacketCaptureApiConfiguration{
			PullSecrets:        pullSecrets,
			Installation:       &i,
			KeyValidatorConfig: config,
			ServerCertSecret:   secret,
		}
		var pc = render.PacketCaptureAPI(cfg)
		Expect(pc.ResolveImages(nil)).To(BeNil())
		resources, _ = pc.Objects()
		return resources
	}

	type expectedResource struct {
		name    string
		ns      string
		group   string
		version string
		kind    string
	}
	// Generate expected resources
	var expectedResources = func(useCSR, enableOIDC bool) []expectedResource {
		var resources = []expectedResource{
			{name: render.PacketCaptureNamespace, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "pull-secret", ns: render.PacketCaptureNamespace, group: "", version: "v1", kind: "Secret"},
			{name: render.PacketCaptureServiceAccountName, ns: render.PacketCaptureNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: render.PacketCaptureClusterRoleName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: render.PacketCaptureClusterRoleBindingName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: render.PacketCaptureDeploymentName, ns: render.PacketCaptureNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: render.PacketCaptureServiceName, ns: render.PacketCaptureNamespace, group: "", version: "v1", kind: "Service"},
		}

		return resources

	}

	// Generate expected environment variables
	var expectedEnvVars = func(enableOIDC bool) []corev1.EnvVar {
		var envVars = []corev1.EnvVar{
			{Name: "PACKETCAPTURE_API_LOG_LEVEL", Value: "Info"},
			{
				Name:  "PACKETCAPTURE_API_HTTPS_KEY",
				Value: "/tigera-packetcapture-server-tls/tls.key",
			},
			{
				Name:  "PACKETCAPTURE_API_HTTPS_CERT",
				Value: "/tigera-packetcapture-server-tls/tls.crt",
			},
		}

		if enableOIDC {
			envVars = append(envVars, []corev1.EnvVar{
				{
					Name:  "PACKETCAPTURE_API_DEX_ENABLED",
					Value: "true",
				},
				{
					Name:  "PACKETCAPTURE_API_DEX_URL",
					Value: "https://tigera-dex.tigera-dex.svc.cluster.local:5556/",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_ENABLED",
					Value: "true",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_ISSUER",
					Value: "https://127.0.0.1/dex",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_JWKSURL",
					Value: "https://tigera-dex.tigera-dex.svc.cluster.local:5556/dex/keys",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_CLIENT_ID",
					Value: "tigera-manager",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_USERNAME_CLAIM",
					Value: "email",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_GROUPS_CLAIM",
					Value: "groups",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_USERNAME_PREFIX",
					Value: "",
				},
				{
					Name:  "PACKETCAPTURE_API_OIDC_AUTH_GROUPS_PREFIX",
					Value: "",
				},
			}...)
		}

		return envVars
	}

	// Generate expected volume mounts
	var expectedVolumeMounts = func() []corev1.VolumeMount {
		var volumeMounts = []corev1.VolumeMount{
			{
				Name:      render.PacketCaptureCertSecret,
				MountPath: "/tigera-packetcapture-server-tls",
				ReadOnly:  true,
			},
		}
		return volumeMounts
	}
	// Generate expected containers
	var expectedContainers = func(enableOIDC bool) []corev1.Container {
		var volumeMounts = expectedVolumeMounts()
		var envVars = expectedEnvVars(enableOIDC)

		return []corev1.Container{
			{
				Name:  render.PacketCaptureContainerName,
				Image: fmt.Sprintf("%s%s:%s", components.TigeraRegistry, components.ComponentPacketCapture.Image, components.ComponentPacketCapture.Version),
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr.BoolToPtr(false),
					Privileged:               ptr.BoolToPtr(false),
					RunAsGroup:               ptr.Int64ToPtr(0),
					RunAsNonRoot:             ptr.BoolToPtr(true),
					RunAsUser:                ptr.Int64ToPtr(1001),
				},
				ReadinessProbe: &corev1.Probe{
					Handler: corev1.Handler{
						HTTPGet: &corev1.HTTPGetAction{
							Path:   "/health",
							Port:   intstr.FromInt(8444),
							Scheme: corev1.URISchemeHTTPS,
						},
					},
					InitialDelaySeconds: 30,
					PeriodSeconds:       10,
				},
				LivenessProbe: &corev1.Probe{
					Handler: corev1.Handler{
						HTTPGet: &corev1.HTTPGetAction{
							Path:   "/health",
							Port:   intstr.FromInt(8444),
							Scheme: corev1.URISchemeHTTPS,
						},
					},
					InitialDelaySeconds: 30,
					PeriodSeconds:       10,
				},
				Env:          envVars,
				VolumeMounts: volumeMounts,
			},
		}
	}

	// Generate expected volumes
	var expectedVolumes = func(useCSR bool) []corev1.Volume {
		var volumes []corev1.Volume
		if useCSR {
			volumes = append(volumes, corev1.Volume{
				Name: render.PacketCaptureCertSecret,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			})
		} else {

			volumes = append(volumes, corev1.Volume{
				Name: render.PacketCaptureCertSecret,
				VolumeSource: corev1.VolumeSource{
					Secret: &corev1.SecretVolumeSource{
						SecretName:  render.PacketCaptureCertSecret,
						DefaultMode: ptr.Int32ToPtr(420),
					},
				},
			})

		}

		return volumes
	}

	var checkPacketCaptureResources = func(resources []client.Object, useCSR, enableOIDC bool) {
		for i, expectedRes := range expectedResources(useCSR, enableOIDC) {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}
		Expect(len(resources)).To(Equal(len(expectedResources(useCSR, enableOIDC))))

		// Check deployment
		deployment := rtest.GetResource(resources, render.PacketCaptureDeploymentName, render.PacketCaptureNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())

		// Check containers
		Expect(deployment.Spec.Template.Spec.Containers).To(ConsistOf(expectedContainers(enableOIDC)))

		// Check init containers
		if useCSR {
			Expect(len(deployment.Spec.Template.Spec.InitContainers)).To(Equal(1))
			Expect(deployment.Spec.Template.Spec.InitContainers[0].Name).To(Equal(fmt.Sprintf("%s-key-cert-provisioner", render.PacketCaptureCertSecret)))
		}

		// Check volumes
		Expect(deployment.Spec.Template.Spec.Volumes).To(ConsistOf(expectedVolumes(useCSR)))

		// Check annotations
		if !useCSR {
			Expect(deployment.Spec.Template.Annotations).To(HaveKeyWithValue("hash.operator.tigera.io/tigera-packetcapture-server-tls", Not(BeEmpty())))
		}

		// Check permissions
		clusterRole := rtest.GetResource(resources, render.PacketCaptureClusterRoleName, "", "rbac.authorization.k8s.io", "v1", "ClusterRole").(*rbacv1.ClusterRole)
		Expect(clusterRole.Rules).To(ConsistOf([]rbacv1.PolicyRule{
			{
				APIGroups: []string{"authorization.k8s.io"},
				Resources: []string{"subjectaccessreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"authentication.k8s.io"},
				Resources: []string{"tokenreviews"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"packetcaptures"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{"projectcalico.org"},
				Resources: []string{"packetcaptures/status"},
				Verbs:     []string{"update"},
			},
		}))
		clusterRoleBinding := rtest.GetResource(resources, render.PacketCaptureClusterRoleBindingName, "", "rbac.authorization.k8s.io", "v1", "ClusterRoleBinding").(*rbacv1.ClusterRoleBinding)
		Expect(clusterRoleBinding.RoleRef.Name).To(Equal(render.PacketCaptureClusterRoleName))
		Expect(clusterRoleBinding.Subjects).To(ConsistOf([]rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      render.PacketCaptureServiceAccountName,
				Namespace: render.PacketCaptureNamespace,
			},
		}))

		// Check service
		service := rtest.GetResource(resources, render.PacketCaptureServiceName, render.PacketCaptureNamespace, "", "v1", "Service").(*corev1.Service)
		Expect(service.Spec.Ports).To(ConsistOf([]corev1.ServicePort{
			{
				Name:       render.PacketCaptureName,
				Port:       443,
				Protocol:   corev1.ProtocolTCP,
				TargetPort: intstr.FromInt(8444),
			}}))
	}

	It("should render all resources for default installation", func() {
		var resources = renderPacketCapture(defaultInstallation, nil)

		checkPacketCaptureResources(resources, false, false)
	})

	It("should render controlPlaneTolerations", func() {
		t := corev1.Toleration{
			Key:      "foo",
			Operator: corev1.TolerationOpEqual,
			Value:    "bar",
		}
		var resources = renderPacketCapture(operatorv1.InstallationSpec{
			ControlPlaneTolerations: []corev1.Toleration{t},
		}, nil)

		checkPacketCaptureResources(resources, false, false)

		deployment := rtest.GetResource(resources, render.PacketCaptureDeploymentName, render.PacketCaptureNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment).NotTo(BeNil())
		Expect(deployment.Spec.Template.Spec.Tolerations).Should(ContainElements(t, rmeta.TolerateCriticalAddonsOnly, rmeta.TolerateMaster))
	})

	It("should render all resources for an installation with certificate management", func() {
		ca, _ := tls.MakeCA(rmeta.DefaultOperatorCASignerName())
		cert, _, _ := ca.Config.GetPEMBytes() // create a valid pem block
		installation := operatorv1.InstallationSpec{CertificateManagement: &operatorv1.CertificateManagement{CACert: cert}}
		certificateManager, err := certificatemanager.Create(cli, &installation, clusterDomain)
		Expect(err).NotTo(HaveOccurred())
		secret, err = certificateManager.GetOrCreateKeyPair(cli, render.PacketCaptureCertSecret, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		var resources = renderPacketCapture(installation, nil)
		checkPacketCaptureResources(resources, true, false)
	})

	It("should render all resources for an installation with oidc configured", func() {
		authentication := &operatorv1.Authentication{
			Spec: operatorv1.AuthenticationSpec{
				ManagerDomain: "https://127.0.0.1",
				OIDC:          &operatorv1.AuthenticationOIDC{IssuerURL: "https://accounts.google.com", UsernameClaim: "email"}}}

		var dexCfg = render.NewDexKeyValidatorConfig(authentication, nil, dns.DefaultClusterDomain)
		var resources = renderPacketCapture(defaultInstallation, dexCfg)

		checkPacketCaptureResources(resources, false, true)
	})
})
