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

package helpers

import (
	operatorv1 "github.com/tigera/operator/api/v1"
)

func ensureTyphaMetadataNotNil(install *operatorv1.Installation) {
	if install.Spec.TyphaDeployment == nil {
		install.Spec.TyphaDeployment = &operatorv1.TyphaDeployment{
			Metadata: &operatorv1.Metadata{},
		}
	}
	if install.Spec.TyphaDeployment.Metadata == nil {
		install.Spec.TyphaDeployment.Metadata = &operatorv1.Metadata{}
	}
}

func EnsureTyphaAnnotationsNotNil(install *operatorv1.Installation) {
	ensureTyphaMetadataNotNil(install)
	if install.Spec.TyphaDeployment.Metadata.Annotations == nil {
		install.Spec.TyphaDeployment.Metadata.Annotations = map[string]string{}
	}
}

func EnsureTyphaLabelsNotNil(install *operatorv1.Installation) {
	ensureTyphaMetadataNotNil(install)
	if install.Spec.TyphaDeployment.Metadata.Labels == nil {
		install.Spec.TyphaDeployment.Metadata.Labels = map[string]string{}
	}
}

func EnsureTyphaSpecNotNil(install *operatorv1.Installation) {
	if install.Spec.TyphaDeployment == nil {
		install.Spec.TyphaDeployment = &operatorv1.TyphaDeployment{
			Spec: &operatorv1.TyphaDeploymentSpec{},
		}
	}
	if install.Spec.TyphaDeployment.Spec == nil {
		install.Spec.TyphaDeployment.Spec = &operatorv1.TyphaDeploymentSpec{}
	}
}

func ensureTyphaPodTemplateMetadataNotNil(install *operatorv1.Installation) {
	if install.Spec.TyphaDeployment == nil {
		install.Spec.TyphaDeployment = &operatorv1.TyphaDeployment{
			Spec: &operatorv1.TyphaDeploymentSpec{
				Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
					Metadata: &operatorv1.Metadata{},
				},
			},
		}
	}
	if install.Spec.TyphaDeployment.Spec == nil {
		install.Spec.TyphaDeployment.Spec = &operatorv1.TyphaDeploymentSpec{
			Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
				Metadata: &operatorv1.Metadata{},
			},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template == nil {
		install.Spec.TyphaDeployment.Spec.Template = &operatorv1.TyphaDeploymentPodTemplateSpec{
			Metadata: &operatorv1.Metadata{},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template.Metadata == nil {
		install.Spec.TyphaDeployment.Spec.Template.Metadata = &operatorv1.Metadata{}
	}
}

func EnsureTyphaPodTemplateAnnotationsNotNil(install *operatorv1.Installation) {
	ensureTyphaPodTemplateMetadataNotNil(install)
	if install.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations == nil {
		install.Spec.TyphaDeployment.Spec.Template.Metadata.Annotations = map[string]string{}
	}
}

func EnsureTyphaPodTemplateLabelsNotNil(install *operatorv1.Installation) {
	ensureTyphaPodTemplateMetadataNotNil(install)
	if install.Spec.TyphaDeployment.Spec.Template.Metadata.Labels == nil {
		install.Spec.TyphaDeployment.Spec.Template.Metadata.Labels = map[string]string{}
	}
}

func EnsureTyphaContainersNotNil(install *operatorv1.Installation) {
	EnsureTyphaPodSpecNotNil(install)
	if install.Spec.TyphaDeployment.Spec.Template.Spec.Containers == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec.Containers = []operatorv1.TyphaDeploymentContainer{}
	}
}

func EnsureTyphaInitContainersNotNil(install *operatorv1.Installation) {
	EnsureTyphaPodSpecNotNil(install)
	if install.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers = []operatorv1.TyphaDeploymentInitContainer{}
	}
}

func EnsureTyphaNodeSelectorNotNil(install *operatorv1.Installation) {
	EnsureTyphaPodSpecNotNil(install)
	if install.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec.NodeSelector = map[string]string{}
	}
}

func EnsureTyphaPodSpecNotNil(install *operatorv1.Installation) {
	if install.Spec.TyphaDeployment == nil {
		install.Spec.TyphaDeployment = &operatorv1.TyphaDeployment{
			Spec: &operatorv1.TyphaDeploymentSpec{
				Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
					Spec: &operatorv1.TyphaDeploymentPodSpec{},
				},
			},
		}
	}
	if install.Spec.TyphaDeployment.Spec == nil {
		install.Spec.TyphaDeployment.Spec = &operatorv1.TyphaDeploymentSpec{
			Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
				Spec: &operatorv1.TyphaDeploymentPodSpec{},
			},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template == nil {
		install.Spec.TyphaDeployment.Spec.Template = &operatorv1.TyphaDeploymentPodTemplateSpec{
			Spec: &operatorv1.TyphaDeploymentPodSpec{},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template.Spec == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec = &operatorv1.TyphaDeploymentPodSpec{}
	}
}
