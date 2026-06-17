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

package utils_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/k8sapi"
	"github.com/tigera/operator/pkg/controller/utils"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/enterprise"
	"github.com/tigera/operator/pkg/extensions"
	"github.com/tigera/operator/pkg/render"
)

// This exercises the full path comment-by-comment: a real render component goes
// through CreateOrUpdateOrDelete with an enterprise RenderContext, and the
// registered modifier must match the real render output by name. If render ever
// renames the typha ClusterRole, the modifier silently no-ops and this fails.
var _ = Describe("componentHandler enterprise modifier integration", func() {
	It("applies the enterprise typha modifier to real render output", func() {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		cli := ctrlrfake.DefaultFakeClientBuilder(scheme).Build()

		certManager, err := certificatemanager.Create(cli, nil, "", common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		nodeKeyPair, err := certManager.GetOrCreateKeyPair(cli, render.NodeTLSSecretName, common.OperatorNamespace(), []string{render.FelixCommonName})
		Expect(err).NotTo(HaveOccurred())
		typhaKeyPair, err := certManager.GetOrCreateKeyPair(cli, render.TyphaTLSSecretName, common.OperatorNamespace(), []string{render.TyphaCommonName})
		Expect(err).NotTo(HaveOccurred())

		instance := &operatorv1.InstallationSpec{
			Variant: operatorv1.CalicoEnterprise,
			CNI:     &operatorv1.CNISpec{Type: operatorv1.PluginCalico},
		}
		comp := render.Typha(&render.TyphaConfiguration{
			K8sServiceEp:    k8sapi.ServiceEndpoint{},
			Installation:    instance,
			ClusterDomain:   dns.DefaultClusterDomain,
			FelixHealthPort: 9099,
			TLS: &render.TyphaNodeTLS{
				TrustedBundle:   certManager.CreateTrustedBundle(),
				TyphaSecret:     typhaKeyPair,
				TyphaCommonName: render.TyphaCommonName,
				NodeSecret:      nodeKeyPair,
				NodeCommonName:  render.FelixCommonName,
			},
		})

		renderCtx := extensions.RenderContext{Installation: instance}
		handler := utils.NewComponentHandler(logf.Log, cli, scheme, nil, utils.WithRenderContext(renderCtx), utils.WithExtensions(enterprise.New()))
		Expect(handler.CreateOrUpdateOrDelete(context.Background(), comp, nil)).NotTo(HaveOccurred())

		role := &rbacv1.ClusterRole{}
		Expect(cli.Get(context.Background(), client.ObjectKey{Name: "calico-typha"}, role)).NotTo(HaveOccurred())
		Expect(role.Rules).To(ContainElement(HaveField("Resources", ContainElement("licensekeys"))))
	})
})
