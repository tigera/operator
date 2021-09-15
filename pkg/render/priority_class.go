// Copyright (c) 2019, 2021 Tigera, Inc. All rights reserved.

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

package render

import (
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	schedv1 "k8s.io/api/scheduling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/api/v1"
)

const (
	CalicoPriorityClassName  = "calico-priority"
	NodePriorityClassName    = "system-node-critical"
	ClusterPriorityClassName = "system-cluster-critical"
)

func setNodeCriticalPod(t *corev1.PodTemplateSpec) {
	t.Spec.PriorityClassName = NodePriorityClassName
}

func SetClusterCriticalPod(t *corev1.PodTemplateSpec) {
	t.Spec.PriorityClassName = ClusterPriorityClassName
}

func setCalicoCriticalPod(t *v1.PodTemplateSpec) {
	t.Spec.PriorityClassName = CalicoPriorityClassName
}

func PriorityClassDefinitions() Component {
	return &priorityClassComponent{}
}

type priorityClassComponent struct {
}

func (c *priorityClassComponent) ResolveImages(is *operator.ImageSet) error {
	// No images to resolve
	return nil
}

func (c *priorityClassComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

func (c *priorityClassComponent) Objects() ([]client.Object, []client.Object) {
	return []client.Object{c.calicoPriority()}, nil
}

func (c *priorityClassComponent) Ready() bool {
	return true
}

func (c *priorityClassComponent) calicoPriority() *schedv1.PriorityClass {
	return &schedv1.PriorityClass{
		TypeMeta: metav1.TypeMeta{Kind: "PriorityClass", APIVersion: "scheduling.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: PriorityClassName,
		},
		// The highest value setable in a priority class by a user is 1000000000.
		Value:         1000000000,
		GlobalDefault: false,
		Description:   "Priority class for Calico resources that should have a high priority",
	}
}
