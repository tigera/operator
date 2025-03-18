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

package goldmane_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/resource"

	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Applying overrides", func() {
	It("Should apply overrides", func() {

		goldmaneResources := &corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
			Requests: corev1.ResourceList{
				"storage": resource.MustParse("10Gi"),
			},
		}

		overrides := &operatorv1.GoldmaneDeployment{
			Spec: &operatorv1.GoldmaneDeploymentSpec{
				Template: &operatorv1.GoldmaneDeploymentPodTemplateSpec{

					Spec: &operatorv1.GoldmaneDeploymentPodSpec{

						Containers: []operatorv1.GoldmaneDeploymentContainer{

							{
								Name:      "goldmane",
								Resources: goldmaneResources,
							},
						},
					},
				},
			},
		}

		// Must implement a function with the following definition:
		// `func GetOverriddenGoldmaneDeployment(overrides *operatorv1.GoldmaneDeployment) (*appsv1.Deployment, error)`
		deployment, err := GetOverriddenGoldmaneDeployment(overrides)
		Expect(err).ShouldNot(HaveOccurred())

		Expect(deployment.Spec.Template.Spec.Containers[0].Resources).To(Equal(*goldmaneResources))

	})
})
