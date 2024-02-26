// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package components

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

type ContainerResources struct {
	CPURequest    string
	CPULimit      string
	MemoryRequest string
	MemoryLimit   string
}

var (
	ResourceCSRInitContainer = ContainerResources{
		CPURequest:    "10m",
		CPULimit:      "10m",
		MemoryRequest: "50Mi",
		MemoryLimit:   "50Mi",
	}
)

func GetContainerResources(r ContainerResources) corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			"cpu":    resource.MustParse(r.CPURequest),
			"memory": resource.MustParse(r.MemoryRequest),
		},
		Limits: corev1.ResourceList{
			"cpu":    resource.MustParse(r.CPULimit),
			"memory": resource.MustParse(r.MemoryLimit),
		},
	}
}
