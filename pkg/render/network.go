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
	"k8s.io/apimachinery/pkg/runtime"
)

// Network creates network configuration.
func Network(cr *operator.Installation, openshift bool) Component {
	subs := []Component{
		PriorityClassDefinitions(cr),
		CustomResourceDefinitions(cr),
		Node(cr, openshift),
		KubeControllers(cr),
	}
	return &networkComponent{
		cr:        cr,
		openshift: openshift,
		subs:      subs,
	}
}

type networkComponent struct {
	cr        *operator.Installation
	openshift bool
	subs      []Component
}

func (c *networkComponent) Objects() []runtime.Object {
	objs := []runtime.Object{
		createNamespace(calicoNamespace, c.openshift),
	}
	for _, sub := range c.subs {
		objs = append(objs, sub.Objects()...)
	}
	return objs
}

func (c *networkComponent) Ready() bool {
	return true
}
