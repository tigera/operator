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

package csr_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/controller/monitor"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	rmonitor "github.com/tigera/operator/pkg/render/monitor"
)

var _ = Describe("CSR extension", func() {
	var cli client.Client

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
	})

	It("makes the Prometheus server certificate signable", func() {
		assets := ext.CSR().AllowedAssets(dns.DefaultClusterDomain)
		asset, ok := assets[rmonitor.PrometheusServerTLSSecretName]
		Expect(ok).To(BeTrue())
		Expect(asset.ServiceAccountName).To(Equal(rmonitor.PrometheusServiceAccountName))
		Expect(asset.ServiceAccountNamespace).To(Equal(rmonitor.TigeraPrometheusObjectName))
		Expect(asset.ValidDNSNames).To(Equal(monitor.PrometheusTLSServerDNSNames(dns.DefaultClusterDomain)))
	})

	It("needs the CSR role when external Prometheus is configured", func() {
		Expect(cli.Create(ctx, &operatorv1.Monitor{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec:       operatorv1.MonitorSpec{ExternalPrometheus: &operatorv1.ExternalPrometheus{Namespace: "default"}},
		})).NotTo(HaveOccurred())
		Expect(ext.CSR().NeedsCSRRole(ctx, cli)).To(BeTrue())
	})

	It("needs the CSR role when a NonClusterHost exists", func() {
		Expect(cli.Create(ctx, &operatorv1.NonClusterHost{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())
		Expect(ext.CSR().NeedsCSRRole(ctx, cli)).To(BeTrue())
	})

	It("still checks for a NonClusterHost when no Monitor exists", func() {
		Expect(ext.CSR().NeedsCSRRole(ctx, cli)).To(BeFalse())

		Expect(cli.Create(ctx, &operatorv1.NonClusterHost{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())
		Expect(ext.CSR().NeedsCSRRole(ctx, cli)).To(BeTrue())
	})

	It("does not need the CSR role when Prometheus is internal", func() {
		Expect(cli.Create(ctx, &operatorv1.Monitor{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
		})).NotTo(HaveOccurred())
		Expect(ext.CSR().NeedsCSRRole(ctx, cli)).To(BeFalse())
	})
})
