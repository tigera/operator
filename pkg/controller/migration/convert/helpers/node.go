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

func ensureCalicoNodeMetadataNotNil(install *operatorv1.Installation) {
	if install.Spec.CalicoNodeDaemonSet == nil {
		install.Spec.CalicoNodeDaemonSet = &operatorv1.CalicoNodeDaemonSet{
			Metadata: &operatorv1.Metadata{},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Metadata == nil {
		install.Spec.CalicoNodeDaemonSet.Metadata = &operatorv1.Metadata{}
	}
}

func EnsureCalicoNodeAnnotationsNotNil(install *operatorv1.Installation) {
	ensureCalicoNodeMetadataNotNil(install)
	if install.Spec.CalicoNodeDaemonSet.Metadata.Annotations == nil {
		install.Spec.CalicoNodeDaemonSet.Metadata.Annotations = map[string]string{}
	}
}

func EnsureCalicoNodeLabelsNotNil(install *operatorv1.Installation) {
	ensureCalicoNodeMetadataNotNil(install)
	if install.Spec.CalicoNodeDaemonSet.Metadata.Labels == nil {
		install.Spec.CalicoNodeDaemonSet.Metadata.Labels = map[string]string{}
	}
}

func ensureCalicoNodePodTemplateMetadataNotNil(install *operatorv1.Installation) {
	if install.Spec.CalicoNodeDaemonSet == nil {
		install.Spec.CalicoNodeDaemonSet = &operatorv1.CalicoNodeDaemonSet{
			Spec: &operatorv1.CalicoNodeDaemonSetSpec{
				Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
					Metadata: &operatorv1.Metadata{},
				},
			},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec == nil {
		install.Spec.CalicoNodeDaemonSet.Spec = &operatorv1.CalicoNodeDaemonSetSpec{
			Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
				Metadata: &operatorv1.Metadata{},
			},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template = &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
			Metadata: &operatorv1.Metadata{},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata = &operatorv1.Metadata{}
	}
}

func EnsureCalicoNodePodTemplateAnnotationsNotNil(install *operatorv1.Installation) {
	ensureCalicoNodePodTemplateMetadataNotNil(install)
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Annotations = map[string]string{}
	}
}

func EnsureCalicoNodePodTemplateLabelsNotNil(install *operatorv1.Installation) {
	ensureCalicoNodePodTemplateMetadataNotNil(install)
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Metadata.Labels = map[string]string{}
	}
}

func EnsureCalicoNodeContainersNotNil(install *operatorv1.Installation) {
	EnsureCalicoNodePodSpecNotNil(install)
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = []operatorv1.CalicoNodeDaemonSetContainer{}
	}
}

func EnsureCalicoNodeInitContainersNotNil(install *operatorv1.Installation) {
	EnsureCalicoNodePodSpecNotNil(install)
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers = []operatorv1.CalicoNodeDaemonSetInitContainer{}
	}
}

func EnsureCalicoNodeNodeSelectorNotNil(install *operatorv1.Installation) {
	EnsureCalicoNodePodSpecNotNil(install)
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector = map[string]string{}
	}
}

func EnsureCalicoNodePodSpecNotNil(install *operatorv1.Installation) {
	if install.Spec.CalicoNodeDaemonSet == nil {
		install.Spec.CalicoNodeDaemonSet = &operatorv1.CalicoNodeDaemonSet{
			Spec: &operatorv1.CalicoNodeDaemonSetSpec{
				Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
					Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{},
				},
			},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec == nil {
		install.Spec.CalicoNodeDaemonSet.Spec = &operatorv1.CalicoNodeDaemonSetSpec{
			Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
				Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{},
			},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template = &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
			Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec = &operatorv1.CalicoNodeDaemonSetPodSpec{}
	}
}
