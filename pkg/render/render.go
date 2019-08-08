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
	// Objects returns all objects this component contains.
	Objects() []runtime.Object

	// Ready returns true if the component is ready to be created.
	Ready() bool
}

// A Renderer is capable of generating components to be installed on the cluster.
type Renderer interface {
	Render() []Component
}

func Calico(cr *operator.Installation, c client.Client, openshift bool) Renderer {
	return calicoRenderer{cr, c, openshift}
}

func TigeraSecure(cr *operator.Installation, c client.Client, openshift bool) Renderer {
	return tigeraRenderer{cr, c, openshift}
}

type calicoRenderer struct {
	installation *operator.Installation
	client       client.Client
	openshift    bool
}

func (r calicoRenderer) Render() []Component {
	var components []Component
	components = appendNotNil(components, CustomResourceDefinitions(r.installation))
	components = appendNotNil(components, PriorityClassDefinitions(r.installation))
	components = appendNotNil(components, Namespaces(r.installation, r.openshift))
	components = appendNotNil(components, Node(r.installation, r.openshift))
	components = appendNotNil(components, KubeControllers(r.installation))
	return components
}

type tigeraRenderer struct {
	installation *operator.Installation
	client       client.Client
	openshift    bool
}

func (r tigeraRenderer) Render() []Component {
	var components []Component
	components = appendNotNil(components, APIServer(r.installation, r.client))
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
