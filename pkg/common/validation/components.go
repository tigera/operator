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

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common/k8svalidation"
	"github.com/tigera/operator/pkg/components"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidateDaemonSetOverrides validates the given DaemonSetOverrides.
// validateContainerFn and validateInitContainerFn are used to validate the
// containers retrieved from the DaemonSetOverrides instance.
func ValidateDaemonSetOverrides(overrides components.DaemonSetOverrides, validateContainerFn func(container operatorv1.Container) error, validateInitContainerFn func(container operatorv1.Container) error) error {
	if md := overrides.GetMetadata(); md != nil {
		if err := validateMetadata(md); err != nil {
			return fmt.Errorf("metadata is invalid: %w", err)
		}
	}
	if minReadySeconds := overrides.GetMinReadySeconds(); minReadySeconds != nil {
		if *minReadySeconds < 0 {
			return fmt.Errorf("spec.MinReadySeconds must be greater than or equal to 0")
		}
	}
	if md := overrides.GetPodTemplateMetadata(); md != nil {
		if err := validateMetadata(md); err != nil {
			return fmt.Errorf("spec.Template.Metadata is invalid: %w", err)
		}
	}
	if initContainers := overrides.GetInitContainers(); len(initContainers) > 0 {
		for _, c := range initContainers {
			if err := validateInitContainerFn(c); err != nil {
				return fmt.Errorf("spec.Template.Spec.InitContainers[%q] is invalid: %w", c.Name, err)
			}
		}
	}
	if containers := overrides.GetContainers(); len(containers) > 0 {
		for _, c := range containers {
			if err := validateContainerFn(c); err != nil {
				return fmt.Errorf("spec.Template.Spec.Containers[%q] is invalid: %w", c.Name, err)
			}
		}
	}
	if affinity := overrides.GetAffinity(); affinity != nil {
		if err := k8svalidation.ValidateAffinity(affinity, field.NewPath("spec", "template", "spec", "affinity")); err != nil {
			return fmt.Errorf("spec.Template.Spec.Affinity is invalid: %w", err.ToAggregate())
		}
	}
	if nodeSelector := overrides.GetNodeSelector(); len(nodeSelector) > 0 {
		if err := k8svalidation.ValidatePodSpecNodeSelector(nodeSelector, field.NewPath("spec", "template", "spec", "nodeSelector")); err != nil {
			return fmt.Errorf("spec.Template.Spec.NodeSelector is invalid: %w", err.ToAggregate())
		}
	}
	if tolerations := overrides.GetTolerations(); len(tolerations) > 0 {
		if err := k8svalidation.ValidateTolerations(tolerations, field.NewPath("spec", "template", "spec", "tolerations")); err != nil {
			return fmt.Errorf("spec.Template.Spec.Tolerations is invalid: %w", err.ToAggregate())
		}
	}
	return nil
}

// validateMetadata validates the given Metadata.
func validateMetadata(metadata *operatorv1.Metadata) error {
	if metadata == nil {
		return nil
	}
	errs := field.ErrorList{}
	errs = append(errs, k8svalidation.ValidateLabels(metadata.Labels, field.NewPath("metadata", "labels"))...)
	errs = append(errs, k8svalidation.ValidateAnnotations(metadata.Annotations, field.NewPath("metadata", "annotations"))...)
	return errs.ToAggregate()
}
