// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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

package render_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tigera/operator/test"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

var _ = Describe("Tigera Secure Fluentd Cloud rendering tests", func() {
	var cfg *render.FluentdConfiguration
	var cli client.Client

	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())

		metricsSecret, err := certificateManager.GetOrCreateKeyPair(cli, render.FluentdPrometheusTLSSecretName, common.OperatorNamespace(), []string{""})
		Expect(err).NotTo(HaveOccurred())

		cfg = &render.FluentdConfiguration{
			LogCollector:  &operatorv1.LogCollector{},
			ClusterDomain: dns.DefaultClusterDomain,
			OSType:        rmeta.OSTypeLinux,
			Installation: &operatorv1.InstallationSpec{
				KubernetesProvider: operatorv1.ProviderNone,
			},
			FluentdKeyPair: metricsSecret,
			TrustedBundle:  certificateManager.CreateTrustedBundle(),
			Cloud:          true,
		}
	})

	Context("single tenant", func() {
		It("should render fluentd Daemonset with all log collection disabled", func() {
			component := render.Fluentd(cfg)
			resources, _ := component.Objects()

			ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))

			container := test.GetContainer(ds.Spec.Template.Spec.Containers, "fluentd")
			Expect(container).NotTo(BeNil())

			Expect(container.Env).To(ContainElements([]v1.EnvVar{
				{Name: "DISABLE_ES_DNS_LOG", Value: "true"},
				{Name: "DISABLE_ES_AUDIT_EE_LOG", Value: "true"},
				{Name: "DISABLE_ES_AUDIT_KUBE_LOG", Value: "true"},
				{Name: "DISABLE_ES_BGP_LOG", Value: "true"},
				{Name: "DISABLE_ES_FLOW_LOG", Value: "true"},
			}))
		})
	})

	Context("multi tenant", func() {
		It("should render fluentd Daemonset with flow log collection enabled and the rest disabled", func() {
			cfg.Tenant = &operatorv1.Tenant{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tenantA",
					Namespace: "tenant-a-namespace",
				},
				Spec: operatorv1.TenantSpec{
					ID: "tenant-a-id",
				},
			}
			component := render.Fluentd(cfg)
			resources, _ := component.Objects()

			ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))

			container := test.GetContainer(ds.Spec.Template.Spec.Containers, "fluentd")
			Expect(container).NotTo(BeNil())
			Expect(container.Env).NotTo(ContainElements([]v1.EnvVar{
				{Name: "DISABLE_ES_FLOW_LOG", Value: "true"},
			}))

			Expect(container.Env).To(ContainElements([]v1.EnvVar{
				{Name: "DISABLE_ES_DNS_LOG", Value: "true"},
				{Name: "DISABLE_ES_AUDIT_EE_LOG", Value: "true"},
				{Name: "DISABLE_ES_AUDIT_KUBE_LOG", Value: "true"},
				{Name: "DISABLE_ES_BGP_LOG", Value: "true"},
			}))
		})
	})

	Context("non-cloud", func() {
		It("should not add the cloud DISABLE_ES_* env vars when Cloud is false", func() {
			cfg.Cloud = false
			component := render.Fluentd(cfg)
			resources, _ := component.Objects()

			ds := rtest.GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*appsv1.DaemonSet)
			container := test.GetContainer(ds.Spec.Template.Spec.Containers, "fluentd")
			Expect(container).NotTo(BeNil())
			Expect(container.Env).NotTo(ContainElements([]v1.EnvVar{
				{Name: "DISABLE_ES_DNS_LOG", Value: "true"},
				{Name: "DISABLE_ES_FLOW_LOG", Value: "true"},
			}))
		})
	})
})
