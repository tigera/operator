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

package installation

import (
	"context"
	"path/filepath"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

var _ = Describe("Installation CRD CEL validation", Serial, func() {
	var (
		testEnv   *envtest.Environment
		dynClient dynamic.Interface
		instGVR   schema.GroupVersionResource
	)

	BeforeEach(func() {
		_, thisFile, _, ok := runtime.Caller(0)
		Expect(ok).To(BeTrue())
		crdDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "config", "crd", "bases")

		testEnv = &envtest.Environment{
			CRDDirectoryPaths:     []string{crdDir},
			ErrorIfCRDPathMissing: true,
		}
		cfg, err := testEnv.Start()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = testEnv.Stop() })

		dynClient, err = dynamic.NewForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())

		instGVR = schema.GroupVersionResource{
			Group:    "operator.tigera.io",
			Version:  "v1",
			Resource: "installations",
		}
	})

	createInstallation := func(v4 map[string]any) error {
		obj := &unstructured.Unstructured{
			Object: map[string]any{
				"apiVersion": "operator.tigera.io/v1",
				"kind":       "Installation",
				"metadata":   map[string]any{"name": "default"},
				"spec": map[string]any{
					"calicoNetwork": map[string]any{
						"nodeAddressAutodetectionV4": v4,
					},
				},
			},
		}
		_, err := dynClient.Resource(instGVR).Create(context.Background(), obj, metav1.CreateOptions{})
		return err
	}

	deleteInstallation := func() {
		_ = dynClient.Resource(instGVR).Delete(context.Background(), "default", metav1.DeleteOptions{})
	}

	patchAutodetection := func(v4 map[string]any) error {
		patch := &unstructured.Unstructured{
			Object: map[string]any{
				"spec": map[string]any{
					"calicoNetwork": map[string]any{
						"nodeAddressAutodetectionV4": v4,
					},
				},
			},
		}
		data, err := patch.MarshalJSON()
		Expect(err).NotTo(HaveOccurred())
		_, err = dynClient.Resource(instGVR).Patch(context.Background(), "default", types.MergePatchType, data, metav1.PatchOptions{})
		return err
	}

	Describe("NodeAddressAutodetection", func() {
		AfterEach(func() {
			deleteInstallation()
		})

		DescribeTable("should allow single or no methods",
			func(v4 map[string]any) {
				Expect(createInstallation(v4)).To(Succeed())
			},
			Entry("empty", map[string]any{}),
			Entry("firstFound", map[string]any{"firstFound": true}),
			Entry("interface", map[string]any{"interface": "eth0"}),
			Entry("skipInterface", map[string]any{"skipInterface": "docker.*"}),
			Entry("canReach", map[string]any{"canReach": "8.8.8.8"}),
			Entry("cidrs", map[string]any{"cidrs": []any{"10.0.0.0/8"}}),
			Entry("kubernetes", map[string]any{"kubernetes": "NodeInternalIP"}),
		)

		DescribeTable("should reject multiple methods",
			func(v4 map[string]any) {
				err := createInstallation(v4)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no more than one autodetection method"))
			},
			Entry("firstFound + interface", map[string]any{"firstFound": true, "interface": "eth0"}),
			Entry("interface + canReach", map[string]any{"interface": "eth0", "canReach": "8.8.8.8"}),
			Entry("kubernetes + cidrs", map[string]any{"kubernetes": "NodeInternalIP", "cidrs": []any{"10.0.0.0/8"}}),
			Entry("three methods", map[string]any{"firstFound": true, "interface": "eth0", "canReach": "8.8.8.8"}),
			Entry("skipInterface + canReach", map[string]any{"skipInterface": "docker.*", "canReach": "8.8.8.8"}),
		)

		It("should reject a merge patch that adds a second method", func() {
			Expect(createInstallation(map[string]any{"firstFound": true})).To(Succeed())

			// Merge patch adds interface alongside firstFound — this is
			// the exact scenario that motivated the CEL rule.
			err := patchAutodetection(map[string]any{"interface": "eth0"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no more than one autodetection method"))
		})
	})
})
