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

package convert

import (
	operatorv1 "github.com/tigera/operator/api/v1"
)

func ensureEmptyCalicoNodeDaemonSetContainers(install *operatorv1.Installation) {
	// Ensure the override field is non nil
	if install.Spec.CalicoNodeDaemonSet == nil {
		install.Spec.CalicoNodeDaemonSet = &operatorv1.CalicoNodeDaemonSet{
			Spec: &operatorv1.CalicoNodeDaemonSetSpec{
				Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
					Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{
						Containers: []operatorv1.CalicoNodeDaemonSetContainer{},
					},
				},
			},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec == nil {
		install.Spec.CalicoNodeDaemonSet.Spec = &operatorv1.CalicoNodeDaemonSetSpec{
			Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
				Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{
					Containers: []operatorv1.CalicoNodeDaemonSetContainer{},
				},
			},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template = &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
			Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{
				Containers: []operatorv1.CalicoNodeDaemonSetContainer{},
			},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec = &operatorv1.CalicoNodeDaemonSetPodSpec{
			Containers: []operatorv1.CalicoNodeDaemonSetContainer{},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec = &operatorv1.CalicoNodeDaemonSetPodSpec{
			Containers: []operatorv1.CalicoNodeDaemonSetContainer{},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = []operatorv1.CalicoNodeDaemonSetContainer{}
	}
}

func ensureEmptyCalicoNodeDaemonSetInitContainers(install *operatorv1.Installation) {
	// Ensure the override field is non nil
	if install.Spec.CalicoNodeDaemonSet == nil {
		install.Spec.CalicoNodeDaemonSet = &operatorv1.CalicoNodeDaemonSet{
			Spec: &operatorv1.CalicoNodeDaemonSetSpec{
				Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
					Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{
						InitContainers: []operatorv1.CalicoNodeDaemonSetInitContainer{},
					},
				},
			},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec == nil {
		install.Spec.CalicoNodeDaemonSet.Spec = &operatorv1.CalicoNodeDaemonSetSpec{
			Template: &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
				Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{
					InitContainers: []operatorv1.CalicoNodeDaemonSetInitContainer{},
				},
			},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template = &operatorv1.CalicoNodeDaemonSetPodTemplateSpec{
			Spec: &operatorv1.CalicoNodeDaemonSetPodSpec{
				InitContainers: []operatorv1.CalicoNodeDaemonSetInitContainer{},
			},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec = &operatorv1.CalicoNodeDaemonSetPodSpec{
			InitContainers: []operatorv1.CalicoNodeDaemonSetInitContainer{},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec = &operatorv1.CalicoNodeDaemonSetPodSpec{
			InitContainers: []operatorv1.CalicoNodeDaemonSetInitContainer{},
		}
	}
	if install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.Containers == nil {
		install.Spec.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers = []operatorv1.CalicoNodeDaemonSetInitContainer{}
	}
}

func ensureEmptyTyphaDeploymentContainers(install *operatorv1.Installation) {
	// Ensure the override field is non nil
	if install.Spec.TyphaDeployment == nil {
		install.Spec.TyphaDeployment = &operatorv1.TyphaDeployment{
			Spec: &operatorv1.TyphaDeploymentSpec{
				Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
					Spec: &operatorv1.TyphaDeploymentPodSpec{
						Containers: []operatorv1.TyphaDeploymentContainer{},
					},
				},
			},
		}
	}
	if install.Spec.TyphaDeployment.Spec == nil {
		install.Spec.TyphaDeployment.Spec = &operatorv1.TyphaDeploymentSpec{
			Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
				Spec: &operatorv1.TyphaDeploymentPodSpec{
					Containers: []operatorv1.TyphaDeploymentContainer{},
				},
			},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template == nil {
		install.Spec.TyphaDeployment.Spec.Template = &operatorv1.TyphaDeploymentPodTemplateSpec{
			Spec: &operatorv1.TyphaDeploymentPodSpec{
				Containers: []operatorv1.TyphaDeploymentContainer{},
			},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template.Spec == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec = &operatorv1.TyphaDeploymentPodSpec{
			Containers: []operatorv1.TyphaDeploymentContainer{},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template.Spec == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec = &operatorv1.TyphaDeploymentPodSpec{
			Containers: []operatorv1.TyphaDeploymentContainer{},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template.Spec.Containers == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec.Containers = []operatorv1.TyphaDeploymentContainer{}
	}
}

func ensureEmptyTyphaDeploymentInitContainers(install *operatorv1.Installation) {
	if install.Spec.TyphaDeployment == nil {
		install.Spec.TyphaDeployment = &operatorv1.TyphaDeployment{
			Spec: &operatorv1.TyphaDeploymentSpec{
				Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
					Spec: &operatorv1.TyphaDeploymentPodSpec{
						InitContainers: []operatorv1.TyphaDeploymentInitContainer{},
					},
				},
			},
		}
	}
	if install.Spec.TyphaDeployment.Spec == nil {
		install.Spec.TyphaDeployment.Spec = &operatorv1.TyphaDeploymentSpec{
			Template: &operatorv1.TyphaDeploymentPodTemplateSpec{
				Spec: &operatorv1.TyphaDeploymentPodSpec{
					InitContainers: []operatorv1.TyphaDeploymentInitContainer{},
				},
			},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template == nil {
		install.Spec.TyphaDeployment.Spec.Template = &operatorv1.TyphaDeploymentPodTemplateSpec{
			Spec: &operatorv1.TyphaDeploymentPodSpec{
				InitContainers: []operatorv1.TyphaDeploymentInitContainer{},
			},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template.Spec == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec = &operatorv1.TyphaDeploymentPodSpec{
			InitContainers: []operatorv1.TyphaDeploymentInitContainer{},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template.Spec == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec = &operatorv1.TyphaDeploymentPodSpec{
			InitContainers: []operatorv1.TyphaDeploymentInitContainer{},
		}
	}
	if install.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers == nil {
		install.Spec.TyphaDeployment.Spec.Template.Spec.InitContainers = []operatorv1.TyphaDeploymentInitContainer{}
	}
}

func ensureEmptyCalicoKubeControllersDeploymentContainers(install *operatorv1.Installation) {
	// Ensure the override field is non nil
	if install.Spec.CalicoKubeControllersDeployment == nil {
		install.Spec.CalicoKubeControllersDeployment = &operatorv1.CalicoKubeControllersDeployment{
			Spec: &operatorv1.CalicoKubeControllersDeploymentSpec{
				Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
					Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
						Containers: []operatorv1.CalicoKubeControllersDeploymentContainer{},
					},
				},
			},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec = &operatorv1.CalicoKubeControllersDeploymentSpec{
			Template: &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
				Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
					Containers: []operatorv1.CalicoKubeControllersDeploymentContainer{},
				},
			},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template = &operatorv1.CalicoKubeControllersDeploymentPodTemplateSpec{
			Spec: &operatorv1.CalicoKubeControllersDeploymentPodSpec{
				Containers: []operatorv1.CalicoKubeControllersDeploymentContainer{},
			},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec = &operatorv1.CalicoKubeControllersDeploymentPodSpec{
			Containers: []operatorv1.CalicoKubeControllersDeploymentContainer{},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec = &operatorv1.CalicoKubeControllersDeploymentPodSpec{
			Containers: []operatorv1.CalicoKubeControllersDeploymentContainer{},
		}
	}
	if install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers == nil {
		install.Spec.CalicoKubeControllersDeployment.Spec.Template.Spec.Containers = []operatorv1.CalicoKubeControllersDeploymentContainer{}
	}
}
