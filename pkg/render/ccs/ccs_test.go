// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ccs_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/test"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render/ccs"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("Tigera Secure CCS rendering tests", func() {
	var (
		cfg *ccs.Config
		cli client.Client
	)

	ccsResources := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			"cpu":     resource.MustParse("2"),
			"memory":  resource.MustParse("300Mi"),
			"storage": resource.MustParse("20Gi"),
		},
		Requests: corev1.ResourceList{
			"cpu":     resource.MustParse("1"),
			"memory":  resource.MustParse("150Mi"),
			"storage": resource.MustParse("10Gi"),
		},
	}

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, "cluster.local", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		bundle := certificateManager.CreateTrustedBundle()
		apiKP, err := certificateManager.GetOrCreateKeyPair(cli, ccs.APICertSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		cfg = &ccs.Config{
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
				Registry:           "testregistry.com/",
			},
			OpenShift:     false,
			ClusterDomain: "cluster.local",
			TrustedBundle: bundle,
			Namespace:     ccs.Namespace,
			APIKeyPair:    apiKP,
		}
	})

	It("should render with default (standalone) ccs configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			// api resources
			{name: ccs.APIResourceName, ns: ccs.Namespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: ccs.APIResourceName, ns: ccs.Namespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: ccs.APIResourceName, ns: ccs.Namespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: ccs.APIResourceName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: ccs.APIResourceName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: ccs.APIResourceName, ns: ccs.Namespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: ccs.APIResourceName, ns: ccs.Namespace, group: "", version: "v1", kind: "Service"},
			{name: ccs.APIAccessPolicyName, ns: ccs.Namespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},

			// controller resources
			{name: ccs.ControllerResourceName, ns: ccs.Namespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: ccs.ControllerResourceName, ns: ccs.Namespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "Role"},
			{name: ccs.ControllerResourceName, ns: ccs.Namespace, group: "rbac.authorization.k8s.io", version: "v1", kind: "RoleBinding"},
			{name: ccs.ControllerResourceName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: ccs.ControllerResourceName, group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: ccs.HostScannerConfigName, ns: ccs.Namespace, group: "", version: "v1", kind: "ConfigMap"},
			{name: ccs.ControllerResourceName, ns: ccs.Namespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: ccs.ControllerAccessPolicyName, ns: ccs.Namespace, group: "projectcalico.org", version: "v3", kind: "NetworkPolicy"},
		}
		// Should render the correct resources.
		component := ccs.CCS(cfg)
		resources, _ := component.Objects()
		Expect(resources).To(HaveLen(len(expectedResources)))

		for i, expectedRes := range expectedResources {
			rtest.ExpectResourceTypeAndObjectMetadata(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		// Check rendering of api deployment.
		d := rtest.GetResource(resources, ccs.APIResourceName, ccs.Namespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		api := d.Spec.Template.Spec.Containers[0]

		apienvs := api.Env
		expectedEnvs := []corev1.EnvVar{
			{Name: "LINSEED_CLIENT_KEY", Value: "/tigera-ccs-api-tls/tls.key"},
			{Name: "LINSEED_CLIENT_CERT", Value: "/tigera-ccs-api-tls/tls.crt"},
			{Name: "HTTPS_CERT", Value: "/tigera-ccs-api-tls/tls.crt"},
			{Name: "HTTPS_KEY", Value: "/tigera-ccs-api-tls/tls.key"},
			{Name: "RESOURCE_AUTHORIZATION_MODE", Value: "k8s_rbac"},
			{Name: "MULTI_CLUSTER_FORWARDING_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
			{Name: "LINSEED_CA", Value: "/etc/pki/tls/certs/tigera-ca-bundle.crt"},
		}
		for _, expected := range expectedEnvs {
			Expect(apienvs).To(ContainElement(expected))
		}

		c := rtest.GetResource(resources, ccs.ControllerResourceName, ccs.Namespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(c.Spec.Template.Spec.Containers).To(HaveLen(1))
		controller := c.Spec.Template.Spec.Containers[0]

		controllerenvs := controller.Env
		controllerExpectedEnvs := []corev1.EnvVar{
			{Name: "CCS_API_CA", Value: "/tigera-ccs-api-tls/tls.crt"},
			{Name: "CCS_API_TOKEN", Value: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
			{Name: "CCS_HOST_SCANNER_YAML_PATH", Value: "/etc/ccs/host-scanner.yaml"},
		}
		for _, expected := range controllerExpectedEnvs {
			Expect(controllerenvs).To(ContainElement(expected))
		}
	})

	It("should render resource requests and limits for ccs components when set", func() {
		cfg.ComplianceConfigurationSecurity = &operatorv1.ComplianceConfigurationSecurity{
			Spec: operatorv1.ComplianceConfigurationSecuritySpec{
				CCSAPIDeployment: &operatorv1.CCSAPIDeployment{
					Spec: &operatorv1.CCSAPIDeploymentSpec{
						Template: &operatorv1.CCSAPIDeploymentPodTemplateSpec{
							Spec: &operatorv1.CCSAPIDeploymentPodSpec{
								Containers: []operatorv1.CCSAPIDeploymentContainer{{
									Name:      "tigera-ccs-api",
									Resources: &ccsResources,
								}},
							},
						},
					},
				},
				CCSControllerDeployment: &operatorv1.CCSControllerDeployment{
					Spec: &operatorv1.CCSControllerDeploymentSpec{
						Template: &operatorv1.CCSControllerDeploymentPodTemplateSpec{
							Spec: &operatorv1.CCSControllerDeploymentPodSpec{
								Containers: []operatorv1.CCSControllerDeploymentContainer{{
									Name:      "tigera-ccs-controller",
									Resources: &ccsResources,
								}},
							},
						},
					},
				},
			},
		}

		component := ccs.CCS(cfg)
		resources, _ := component.Objects()
		d, ok := rtest.GetResource(resources, "tigera-ccs-api", "tigera-compliance", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		container := test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-ccs-api")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(ccsResources))

		d, ok = rtest.GetResource(resources, "tigera-ccs-controller", "tigera-compliance", "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(ok).To(BeTrue())
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		container = test.GetContainer(d.Spec.Template.Spec.Containers, "tigera-ccs-controller")
		Expect(container).NotTo(BeNil())
		Expect(container.Resources).To(Equal(ccsResources))
	})

})
