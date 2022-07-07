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

package components

import (
	opv1 "github.com/tigera/operator/api/v1"

	corev1 "k8s.io/api/core/v1"
)

// DaemonSetOverrides represents a type that contains the data needed to override a component DaemonSet resource.
type DaemonSetOverrides interface {
	GetMetadata() *opv1.Metadata
	GetMinReadySeconds() *int32
	GetPodTemplateMetadata() *opv1.Metadata
	GetInitContainers() []opv1.Container
	GetContainers() []opv1.Container
	GetAffinity() *corev1.Affinity
	GetNodeSelector() map[string]string
	GetTolerations() []corev1.Toleration
}
