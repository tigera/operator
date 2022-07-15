// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package validation

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/tigera/operator/pkg/common/k8svalidation"
	"github.com/tigera/operator/pkg/render"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateTyphaDeploymentContainer validates the given container is a valid typha Deployment container.
func ValidateTyphaDeploymentContainer(container corev1.Container) error {
	if container.Name != render.TyphaContainerName {
		return fmt.Errorf("Installation spec.TyphaDeployment.Spec.Template.Spec.Containers[%q] is not a supported container", container.Name)
	}

	errs := k8svalidation.ValidateResourceRequirements(&container.Resources, field.NewPath("spec", "template", "spec", "containers"))
	return errs.ToAggregate()
}

// ValidateTyphaDeploymentInitContainer validates the given container is a valid typha Deployment init container.
func ValidateTyphaDeploymentInitContainer(container corev1.Container) error {
	if container.Name != render.TyphaInitContainerName {
		return fmt.Errorf("Installation spec.TyphaDeployment.Spec.Template.Spec.InitContainers[%q] is not a supported init container", container.Name)
	}

	errs := k8svalidation.ValidateResourceRequirements(&container.Resources, field.NewPath("spec", "template", "spec", "initContainers"))
	return errs.ToAggregate()
}
