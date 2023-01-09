// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package cloudrbac_test

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/cloudrbac"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	opcomponents "github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/dns"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("Role rendering tests (Calico Cloud)", func() {

	var cfg *cloudrbac.Configuration

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()
		certificateManager, err := certificatemanager.Create(cli, nil, dns.DefaultClusterDomain)
		Expect(err).NotTo(HaveOccurred())
		dnsNames := dns.GetServiceDNSNames(cloudrbac.RBACApiName, cloudrbac.RBACApiNamespace, "")
		keyPair, err := certificateManager.GetOrCreateKeyPair(cli, cloudrbac.RBACAPICertSecretName, cloudrbac.RBACApiNamespace, dnsNames)
		Expect(err).NotTo(HaveOccurred())

		cfg = &cloudrbac.Configuration{
			Installation:  &operatorv1.InstallationSpec{},
			TLSKeyPair:    keyPair,
			TrustedBundle: certificateManager.CreateTrustedBundle(),
			KeyValidatorConfig: render.NewDexKeyValidatorConfig(&operatorv1.Authentication{
				Spec: operatorv1.AuthenticationSpec{
					ManagerDomain: "https://127.0.0.1",
					OIDC: &operatorv1.AuthenticationOIDC{
						IssuerURL:     "https://accounts.google.com",
						UsernameClaim: "email",
					}}}, nil, dns.DefaultClusterDomain),
		}
	})

	It("should render RBAC Api objects", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: cloudrbac.RBACApiNamespace, group: "", version: "v1", kind: "Namespace"},
			{name: cloudrbac.RBACApiServiceAccountName, ns: cloudrbac.RBACApiNamespace, group: "", version: "v1", kind: "ServiceAccount"},
			{name: cloudrbac.RBACApiClusterRoleName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: cloudrbac.RBACApiClusterRoleBindingName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: cloudrbac.RBACApiNetworkAdminClusterRoleBindingName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: cloudrbac.RBACApiDeploymentName, ns: cloudrbac.RBACApiNamespace, group: "apps", version: "v1", kind: "Deployment"},
			{name: cloudrbac.RBACApiServiceName, ns: cloudrbac.RBACApiNamespace, group: "", version: "v1", kind: "Service"},
		}

		component := cloudrbac.RBACApi(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())
		resources, _ := component.Objects()
		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		deployment := rtest.GetResource(resources, cloudrbac.RBACApiDeploymentName, cloudrbac.RBACApiNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(deployment.Spec.Template.Spec.Containers).To(HaveLen(1))

		container := deployment.Spec.Template.Spec.Containers[0]
		Expect(container.Image).Should(Equal(opcomponents.CloudRegistry + "tigera/cc-rbac-api:" + opcomponents.ComponentCloudRBACApi.Version))

		securityContext := container.SecurityContext
		Expect(*securityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*securityContext.Privileged).To(BeFalse())
		Expect(*securityContext.RunAsGroup).To(BeEquivalentTo(0))
		Expect(*securityContext.RunAsNonRoot).To(BeTrue())
		Expect(*securityContext.RunAsUser).To(BeEquivalentTo(1000))
		Expect(*securityContext.SeccompProfile).To(BeEquivalentTo(corev1.SeccompProfile{
			Type: corev1.SeccompProfileTypeRuntimeDefault,
		}))
		Expect(securityContext.Capabilities).To(BeEquivalentTo(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
	})
})
