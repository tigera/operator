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

func ensureAPIServerMetadataNotNil(apiServer *operatorv1.APIServer) {
	if apiServer.Spec.APIServerDeployment == nil {
		apiServer.Spec.APIServerDeployment = &operatorv1.APIServerDeployment{
			Metadata: &operatorv1.Metadata{},
		}
	}
	if apiServer.Spec.APIServerDeployment.Metadata == nil {
		apiServer.Spec.APIServerDeployment.Metadata = &operatorv1.Metadata{}
	}
}

func EnsureAPIServerAnnotationsNotNil(apiServer *operatorv1.APIServer) {
	ensureAPIServerMetadataNotNil(apiServer)
	if apiServer.Spec.APIServerDeployment.Metadata.Annotations == nil {
		apiServer.Spec.APIServerDeployment.Metadata.Annotations = map[string]string{}
	}
}

func EnsureAPIServerLabelsNotNil(apiServer *operatorv1.APIServer) {
	ensureAPIServerMetadataNotNil(apiServer)
	if apiServer.Spec.APIServerDeployment.Metadata.Labels == nil {
		apiServer.Spec.APIServerDeployment.Metadata.Labels = map[string]string{}
	}
}

func EnsureAPIServerSpecNotNil(apiServer *operatorv1.APIServer) {
	if apiServer.Spec.APIServerDeployment == nil {
		apiServer.Spec.APIServerDeployment = &operatorv1.APIServerDeployment{
			Spec: &operatorv1.APIServerDeploymentSpec{},
		}
	}
	if apiServer.Spec.APIServerDeployment.Spec == nil {
		apiServer.Spec.APIServerDeployment.Spec = &operatorv1.APIServerDeploymentSpec{}
	}
}

func ensureAPIServerPodTemplateMetadataNotNil(apiServer *operatorv1.APIServer) {
	if apiServer.Spec.APIServerDeployment == nil {
		apiServer.Spec.APIServerDeployment = &operatorv1.APIServerDeployment{
			Spec: &operatorv1.APIServerDeploymentSpec{
				Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
					Metadata: &operatorv1.Metadata{},
				},
			},
		}
	}
	if apiServer.Spec.APIServerDeployment.Spec == nil {
		apiServer.Spec.APIServerDeployment.Spec = &operatorv1.APIServerDeploymentSpec{
			Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
				Metadata: &operatorv1.Metadata{},
			},
		}
	}
	if apiServer.Spec.APIServerDeployment.Spec.Template == nil {
		apiServer.Spec.APIServerDeployment.Spec.Template = &operatorv1.APIServerDeploymentPodTemplateSpec{
			Metadata: &operatorv1.Metadata{},
		}
	}
	if apiServer.Spec.APIServerDeployment.Spec.Template.Metadata == nil {
		apiServer.Spec.APIServerDeployment.Spec.Template.Metadata = &operatorv1.Metadata{}
	}
}

func EnsureAPIServerPodTemplateAnnotationsNotNil(apiServer *operatorv1.APIServer) {
	ensureAPIServerPodTemplateMetadataNotNil(apiServer)
	if apiServer.Spec.APIServerDeployment.Spec.Template.Metadata.Annotations == nil {
		apiServer.Spec.APIServerDeployment.Spec.Template.Metadata.Annotations = map[string]string{}
	}
}

func EnsureAPIServerPodTemplateLabelsNotNil(apiServer *operatorv1.APIServer) {
	ensureAPIServerPodTemplateMetadataNotNil(apiServer)
	if apiServer.Spec.APIServerDeployment.Spec.Template.Metadata.Labels == nil {
		apiServer.Spec.APIServerDeployment.Spec.Template.Metadata.Labels = map[string]string{}
	}
}

func EnsureAPIServerContainersNotNil(apiServer *operatorv1.APIServer) {
	EnsureAPIServerPodSpecNotNil(apiServer)
	if apiServer.Spec.APIServerDeployment.Spec.Template.Spec.Containers == nil {
		apiServer.Spec.APIServerDeployment.Spec.Template.Spec.Containers = []operatorv1.APIServerDeploymentContainer{}
	}
}

func EnsureAPIServerInitContainersNotNil(apiServer *operatorv1.APIServer) {
	EnsureAPIServerPodSpecNotNil(apiServer)
	if apiServer.Spec.APIServerDeployment.Spec.Template.Spec.InitContainers == nil {
		apiServer.Spec.APIServerDeployment.Spec.Template.Spec.InitContainers = []operatorv1.APIServerDeploymentInitContainer{}
	}
}

func EnsureAPIServerNodeSelectorNotNil(apiServer *operatorv1.APIServer) {
	EnsureAPIServerPodSpecNotNil(apiServer)
	if apiServer.Spec.APIServerDeployment.Spec.Template.Spec.NodeSelector == nil {
		apiServer.Spec.APIServerDeployment.Spec.Template.Spec.NodeSelector = map[string]string{}
	}
}

func EnsureAPIServerPodSpecNotNil(apiServer *operatorv1.APIServer) {
	if apiServer.Spec.APIServerDeployment == nil {
		apiServer.Spec.APIServerDeployment = &operatorv1.APIServerDeployment{
			Spec: &operatorv1.APIServerDeploymentSpec{
				Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
					Spec: &operatorv1.APIServerDeploymentPodSpec{},
				},
			},
		}
	}
	if apiServer.Spec.APIServerDeployment.Spec == nil {
		apiServer.Spec.APIServerDeployment.Spec = &operatorv1.APIServerDeploymentSpec{
			Template: &operatorv1.APIServerDeploymentPodTemplateSpec{
				Spec: &operatorv1.APIServerDeploymentPodSpec{},
			},
		}
	}
	if apiServer.Spec.APIServerDeployment.Spec.Template == nil {
		apiServer.Spec.APIServerDeployment.Spec.Template = &operatorv1.APIServerDeploymentPodTemplateSpec{
			Spec: &operatorv1.APIServerDeploymentPodSpec{},
		}
	}
	if apiServer.Spec.APIServerDeployment.Spec.Template.Spec == nil {
		apiServer.Spec.APIServerDeployment.Spec.Template.Spec = &operatorv1.APIServerDeploymentPodSpec{}
	}
}
