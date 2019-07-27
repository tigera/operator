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

// A Renderer is capable of generating components to be installed on the cluster.
type Renderer interface {
	Render() []Component
}

func New(cr *operator.Installation, client client.Client, openshift bool) Renderer {
	return renderer{cr, client, openshift}
}

type renderer struct {
	installation *operator.Installation
	client       client.Client
	openshift    bool
}

func (r renderer) Render() []Component {
	var components []Component
	components = appendNotNil(components, CustomResourceDefinitions(r.installation))
	components = appendNotNil(components, PriorityClassDefinitions(r.installation))
	components = appendNotNil(components, KubeProxy(r.installation))
	components = appendNotNil(components, Namespaces(r.installation, r.openshift))
	components = appendNotNil(components, Node(r.installation, r.openshift))
	components = appendNotNil(components, KubeControllers(r.installation))
	components = appendNotNil(components, APIServer(r.installation))
	components = appendNotNil(components, Console(r.installation, r.client))
	components = appendNotNil(components, Compliance(r.installation, r.openshift))
	components = appendNotNil(components, IntrusionDetection(r.installation))
	return components
}

func appendNotNil(components []Component, c Component) []Component {
	if c != nil {
		components = append(components, c)
	}
	return components
}
