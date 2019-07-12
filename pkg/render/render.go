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

type Component interface {
	GetObjects() []runtime.Object
	GetComponentDeps() []runtime.Object
}

type component struct {
	objs []runtime.Object
	deps []runtime.Object
}

func (c *component) GetObjects() []runtime.Object {
	return c.objs
}
func (c *component) GetComponentDeps() []runtime.Object {
	return c.deps
}

func Render(cr *operator.Installation) []Component {
	var components []Component
	components = appendNotNil(components, CustomResourceDefinitions(cr))
	components = appendNotNil(components, PriorityClassDefinitions(cr))
	components = appendNotNil(components, KubeProxy(cr))
	components = appendNotNil(components, Namespaces(cr))
	components = appendNotNil(components, Node(cr))
	components = appendNotNil(components, KubeControllers(cr))
	components = appendNotNil(components, APIServer(cr))

	if cr.Spec.Variant == operator.TigeraSecureEnterprise {
		components = appendNotNil(components, Compliance(cr))
	}

	return components
}

func appendNotNil(components []Component, c Component) []Component {
	if c != nil {
		components = append(components, c)
	}
	return components
}
