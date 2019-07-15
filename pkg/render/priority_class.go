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
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	schedv1beta "k8s.io/api/scheduling/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	priorityClassName = "calico-priority"
)

func PriorityClassDefinitions(cr *operator.Installation) Component {
	return &priorityClassComponent{cr: cr}
}

type priorityClassComponent struct {
	cr *operator.Installation
}

func (c *priorityClassComponent) GetObjects() []runtime.Object {
	return []runtime.Object{calicoPriority(c.cr)}
}

func (c *priorityClassComponent) GetComponentDeps() []runtime.Object {
	return nil
}

func (c *priorityClassComponent) Ready(client client.Client) bool {
	return true
}

func calicoPriority(cr *operator.Installation) *schedv1beta.PriorityClass {
	return &schedv1beta.PriorityClass{
		TypeMeta: metav1.TypeMeta{Kind: "PriorityClass", APIVersion: "scheduling.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: priorityClassName,
		},
		// We would prefer to use the same value as system-node-critical (2000001000)
		// but the highest value setable by a user is 1000000000
		// and system-node-critical can only be used in the kube-system namespace
		Value:         1000000000,
		GlobalDefault: false,
		Description:   "Priority class for Calico resources that should have a high priority",
	}
}
