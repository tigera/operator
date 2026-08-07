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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

func nodeDaemonSet(image string, generation, observedGeneration, updated, desired int64) *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{}
	ds.Generation = generation
	ds.Spec.Template.Spec.Containers = []corev1.Container{{Name: "calico-node", Image: image}}
	ds.Status.ObservedGeneration = observedGeneration
	ds.Status.UpdatedNumberScheduled = int32(updated)
	ds.Status.DesiredNumberScheduled = int32(desired)
	return ds
}

var _ = Describe("deferTyphaDeploymentUpdate", func() {
	const (
		oldImage = "docker.io/calico/node:v3.31.3"
		newImage = "docker.io/calico/node:v3.32.1"
	)

	It("does not defer in steady state (image matches, rollout complete)", func() {
		ds := nodeDaemonSet(newImage, 5, 5, 30, 30)
		Expect(deferTyphaDeploymentUpdate(ds, newImage)).To(BeFalse())
	})

	It("defers when a node image change is about to be applied", func() {
		// The cached DaemonSet still has the old image with a completed
		// rollout; this reconcile is about to apply the new image.
		ds := nodeDaemonSet(oldImage, 5, 5, 30, 30)
		Expect(deferTyphaDeploymentUpdate(ds, newImage)).To(BeTrue())
	})

	It("defers while the rollout has not been observed by the DaemonSet controller", func() {
		ds := nodeDaemonSet(newImage, 6, 5, 30, 30)
		Expect(deferTyphaDeploymentUpdate(ds, newImage)).To(BeTrue())
	})

	It("defers while pods are still being updated", func() {
		ds := nodeDaemonSet(newImage, 6, 6, 12, 30)
		Expect(deferTyphaDeploymentUpdate(ds, newImage)).To(BeTrue())
	})

	It("does not defer once all pods are updated, regardless of readiness", func() {
		// Readiness is intentionally not part of the condition: what matters
		// is that no old-version Felix remains, and a permanently unready
		// node must not block Typha updates.
		ds := nodeDaemonSet(newImage, 6, 6, 30, 30)
		ds.Status.NumberReady = 3
		Expect(deferTyphaDeploymentUpdate(ds, newImage)).To(BeFalse())
	})

	It("does not defer when the DaemonSet has no calico-node container", func() {
		ds := nodeDaemonSet(newImage, 5, 5, 30, 30)
		ds.Spec.Template.Spec.Containers = []corev1.Container{{Name: "other", Image: oldImage}}
		Expect(deferTyphaDeploymentUpdate(ds, newImage)).To(BeFalse())
	})
})
