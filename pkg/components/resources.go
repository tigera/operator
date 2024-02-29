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

// ContainerResources represents the resource requirements and limits for a container.
type ContainerResources struct {
	// CPURequest specifies the amount of CPU requested for the container.
	// Specify CPU units using the milliCPU when using less than 1 CPU unit. For example: 1 CPU unit = 1000 millicore or 1000m
	CPURequest string

	// CPULimit specifies the maximum amount of CPU allowed for the container.
	// Specify CPU units using the milliCPU when using less than 1 CPU unit. For example: 1 CPU unit = 1000 millicore or 1000m
	CPULimit string

	// MemoryRequest specifies the amount of memory requested for the container.
	// Use the power-of-two equivalents: Ei, Pi, Ti, Gi, Mi, Ki. For example: 1 Mi = 1000 kibibyte
	MemoryRequest string

	// MemoryLimit specifies the maximum amount of memory allowed for the container.
	// Use the power-of-two equivalents: Ei, Pi, Ti, Gi, Mi, Ki. For example: 1 Mi = 1000 kibibyte
	MemoryLimit string
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
