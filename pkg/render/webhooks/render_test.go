// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package webhooks_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	rtest "github.com/tigera/operator/pkg/render/common/test"
	"github.com/tigera/operator/pkg/render/webhooks"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Webhooks rendering tests", func() {
	var (
		installation       *operatorv1.InstallationSpec
		apiServerSpec      *operatorv1.APIServerSpec
		cfg                *webhooks.Configuration
		certificateManager certificatemanager.CertificateManager
		cli                client.Client
		clusterDomain      = "cluster.local"
	)

	BeforeEach(func() {
		installation = &operatorv1.InstallationSpec{
			Registry: "test-registry.com/",
			Variant:  operatorv1.Calico,
		}
		apiServerSpec = &operatorv1.APIServerSpec{}

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		var err error
		certificateManager, err = certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		dnsNames := dns.GetServiceDNSNames(webhooks.WebhooksName, common.CalicoNamespace, clusterDomain)
		kp, err := certificateManager.GetOrCreateKeyPair(cli, webhooks.WebhooksTLSSecretName, common.OperatorNamespace(), dnsNames)
		Expect(err).NotTo(HaveOccurred())

		cfg = &webhooks.Configuration{
			Installation: installation,
			APIServer:    apiServerSpec,
			KeyPair:      kp,
		}
	})

	It("should render all resources for Calico", func() {
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera." + webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "api.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "ValidatingWebhookConfiguration", APIVersion: "admissionregistration.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}

		rtest.ExpectResources(resources, expectedResources)
	})

	It("should render all resources for Enterprise with the correct image", func() {
		installation.Variant = operatorv1.TigeraSecureEnterprise
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		expectedResources := []client.Object{
			&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"}},
			&v3.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "allow-tigera." + webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"}},
			&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}},
			&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName, Namespace: common.CalicoNamespace}, TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"}},
			&admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "api.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "ValidatingWebhookConfiguration", APIVersion: "admissionregistration.k8s.io/v1"}},
			&admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{Name: "api.projectcalico.org"}, TypeMeta: metav1.TypeMeta{Kind: "MutatingWebhookConfiguration", APIVersion: "admissionregistration.k8s.io/v1"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"}},
			&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: webhooks.WebhooksName}, TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"}},
		}
		rtest.ExpectResources(resources, expectedResources)

		// Verify Enterprise uses the Tigera webhooks image.
		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(dep.Spec.Template.Spec.Containers[0].Image).To(Equal(
			fmt.Sprintf("test-registry.com/%s%s:%s",
				components.TigeraImagePath,
				components.ComponentTigeraWebhooks.Image,
				components.ComponentTigeraWebhooks.Version)))
	})

	It("should apply deployment overrides", func() {
		apiServerSpec.CalicoWebhooksDeployment = &operatorv1.CalicoWebhooksDeployment{
			Spec: &operatorv1.CalicoWebhooksDeploymentSpec{
				Template: &operatorv1.CalicoWebhooksDeploymentPodTemplateSpec{
					Spec: &operatorv1.CalicoWebhooksDeploymentPodSpec{
						NodeSelector: map[string]string{"foo": "bar"},
					},
				},
			},
		}
		component := webhooks.Component(cfg)
		Expect(component.ResolveImages(nil)).NotTo(HaveOccurred())
		resources, _ := component.Objects()

		dep := rtest.GetResource(resources, webhooks.WebhooksName, common.CalicoNamespace, "apps", "v1", "Deployment").(*appsv1.Deployment)
		Expect(dep.Spec.Template.Spec.NodeSelector).To(HaveKeyWithValue("foo", "bar"))
	})
})
