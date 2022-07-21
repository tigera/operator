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

func ensureKubeControllersMetadataNotNil(install *operatorv1.Installation) {
	if install.Spec.CalicoKubeControllersDeployment == nil {
		install.Spec.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
			Metadata: &operatorv1.Metadata{},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Metadata == nil {
		install.Spec.CalicoKubeControllersDeployment.Metadata = &operatorv1.Metadata{}
	}
}

func EnsureKubeControllersAnnotationsNotNil(install *operatorv1.Installation) {
	ensureKubeControllersMetadataNotNil(install)
	if install.Spec.CalicoKubeControllersDeployment.Metadata.Annotations == nil {
		install.Spec.CalicoKubeControllersDeployment.Metadata.Annotations = map[string]string{}
	}
}

func EnsureKubeControllersLabelsNotNil(install *operatorv1.Installation) {
	ensureKubeControllersMetadataNotNil(install)
	if install.Spec.CalicoKubeControllersDeployment.Metadata.Labels == nil {
		install.Spec.CalicoKubeControllersDeployment.Metadata.Labels = map[string]string{}
	}
}

func ensureKubeControllersPodTemplateMetadataNotNil(install *operatorv1.Installation) {
	if install.Spec.CalicoKubeControllersDeployment == nil {
		install.Spec.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
			Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
				Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
					Metadata: &operatorv1.Metadata{},
				},
			},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec = &operatorv1.CalicoKubeControllersDeploymentSpec{
			Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
				Metadata: &operatorv1.Metadata{},
			},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template = &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
			Metadata: &operatorv1.Metadata{},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata = &operatorv1.Metadata{}
	}
}

func EnsureKubeControllersPodTemplateAnnotationsNotNil(install *operatorv1.Installation) {
	ensureKubeControllersPodTemplateMetadataNotNil(install)
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Annotations = map[string]string{}
	}
}

func EnsureKubeControllersPodTemplateLabelsNotNil(install *operatorv1.Installation) {
	ensureKubeControllersPodTemplateMetadataNotNil(install)
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template.Metadata.Labels = map[string]string{}
	}
}

func EnsureKubeControllersContainersNotNil(install *operatorv1.Installation) {
	EnsureKubeControllersPodSpecNotNil(install)
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers = []operatorv1.CalicoKubeControllersDeploymentContainer{}
	}
}

func EnsureKubeControllersPodSpecNotNil(install *operatorv1.Installation) {
	if install.Spec.CalicoKubeControllersDeployment == nil {
		install.Spec.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
			Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
				Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
					Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{},
				},
			},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec = &operatorv1.CalicoKubeControllersDeploymentSpec{
			Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
				Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{},
			},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template = &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
			Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec = &operatorv1.CalicoKubeControllersDeploymentPodSpec{}
	}
}
