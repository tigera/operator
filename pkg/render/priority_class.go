// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	schedv1 "k8s.io/api/scheduling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/api/v1"
)

const (
	PriorityClassName = "calico-priority"
)

func PriorityClassDefinitions() Component {
	return &priorityClassComponent{}
}

type priorityClassComponent struct {
}

func (c *priorityClassComponent) ResolveImages(is *operator.ImageSet) error {
	// No images to resolve
	return nil
}

func (c *priorityClassComponent) SupportedOSType() OSType {
	return OSTypeAny
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
		// We would prefer to use the same value as system-node-critical (2000001000)
		// but the highest value setable by a user is 1000000000
		// and system-node-critical can only be used in the kube-system namespace
		Value:         1000000000,
		GlobalDefault: false,
		Description:   "Priority class for Calico resources that should have a high priority",
	}
}
