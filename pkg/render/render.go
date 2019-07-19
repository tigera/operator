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
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Component interface {
	// GetObjects returns all objects this component contains.
	GetObjects() []runtime.Object

	// GetComponentDeps returns all objects this component depends on.
	GetComponentDeps() []runtime.Object

	// Ready returns true if the component is ready to be created.
	Ready(client client.Client) bool
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
	components = appendNotNil(components, Compliance(cr))
	components = appendNotNil(components, IntrusionDetection(cr))
	components = appendNotNil(components, Console(cr))
	return components
}

func appendNotNil(components []Component, c Component) []Component {
	if c != nil {
		components = append(components, c)
	}
	return components
}
