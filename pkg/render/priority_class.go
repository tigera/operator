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
	"github.com/tigera/operator/pkg/controller/utils"
	schedv1beta "k8s.io/api/scheduling/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	PriorityClassName = "calico-priority"
)

func PriorityClassDefinitions(v *utils.VersionInfo) Component {
	// skip creation of the priorityClass if this is k8s >= v1.17 as we can
	// use system-node-critical outside of the kube-system namespace.
	if v != nil && v.Minor >= 17 {
		return nil
	}
	return &priorityClassComponent{}
}

type priorityClassComponent struct {
}

func (c *priorityClassComponent) SupportedOSType() OSType {
	return OSTypeAny
}

func (c *priorityClassComponent) Objects() ([]runtime.Object, []runtime.Object) {
	return []runtime.Object{c.calicoPriority()}, nil
}

func (c *priorityClassComponent) Ready() bool {
	return true
}

func (c *priorityClassComponent) calicoPriority() *schedv1beta.PriorityClass {
	return &schedv1beta.PriorityClass{
		TypeMeta: metav1.TypeMeta{Kind: "PriorityClass", APIVersion: "scheduling.k8s.io/v1beta1"},
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
