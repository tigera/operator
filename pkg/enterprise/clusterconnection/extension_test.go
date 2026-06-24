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

package clusterconnection_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/contexts"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("clusterconnection enterprise controller extension", func() {
	var cli client.Client

	// controllerContext builds a ControllerContext selecting the enterprise
	// clusterconnection hook against the given client.
	controllerContext := func() contexts.ControllerContext {
		return contexts.ControllerContext{
			RenderContext: render.RenderContext{
				Installation: &operatorv1.InstallationSpec{Variant: operatorv1.CalicoEnterprise},
			},
			Controller: contexts.ClusterConnectionController,
			Ctx:        context.Background(),
			Client:     cli,
		}
	}

	clusterInformation := func() *v3.ClusterInformation {
		return &v3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       v3.ClusterInformationSpec{CNXVersion: "v3.99.0", CalicoVersion: "v3.99.0-calico"},
		}
	}

	newClient := func(objs ...client.Object) client.Client {
		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		return ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(objs...).Build()
	}

	Describe("Validate", func() {
		It("passes when no ManagementCluster exists", func() {
			cli = newClient()
			Expect(ext.Validate(controllerContext())).NotTo(HaveOccurred())
		})

		It("rejects a cluster that is both a management and a managed cluster", func() {
			cli = newClient(&operatorv1.ManagementCluster{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})
			err := ext.Validate(controllerContext())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not supported"))
		})
	})

	Describe("ExtendContext", func() {
		It("reports the managed cluster CNX version", func() {
			cli = newClient(clusterInformation())
			rc, managed, err := ext.ExtendContext(controllerContext())
			Expect(err).NotTo(HaveOccurred())
			Expect(managed).To(BeEmpty())

			data, ok := render.GuardianRenderDataFromContext(rc)
			Expect(ok).To(BeTrue())
			Expect(data.Version).To(Equal("v3.99.0"))
			Expect(data.IncludeEgressNetworkPolicy).To(BeFalse())
		})

		It("enables the egress network policy when the license has the feature", func() {
			license := &v3.LicenseKey{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Status:     v3.LicenseKeyStatus{Features: []string{common.EgressAccessControlFeature}},
			}
			cli = newClient(clusterInformation(), license)
			rc, _, err := ext.ExtendContext(controllerContext())
			Expect(err).NotTo(HaveOccurred())

			data, ok := render.GuardianRenderDataFromContext(rc)
			Expect(ok).To(BeTrue())
			Expect(data.IncludeEgressNetworkPolicy).To(BeTrue())
		})

		It("errors when ClusterInformation is missing", func() {
			cli = newClient()
			_, _, err := ext.ExtendContext(controllerContext())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("ClusterInformation"))
		})
	})
})
