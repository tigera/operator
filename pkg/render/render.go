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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

func Calico(cr *operator.Installation, pullSecrets []*corev1.Secret, p operator.Provider, nc NetworkConfig) Renderer {
	return calicoRenderer{
		installation:  cr,
		pullSecrets:   pullSecrets,
		provider:      p,
		networkConfig: nc,
	}
}

type calicoRenderer struct {
	installation  *operator.Installation
	pullSecrets   []*corev1.Secret
	provider      operator.Provider
	networkConfig NetworkConfig
}

func (r calicoRenderer) Render() []Component {
	var components []Component
	components = appendNotNil(components, CustomResourceDefinitions(r.installation))
	components = appendNotNil(components, PriorityClassDefinitions(r.installation))
	components = appendNotNil(components, Namespaces(r.installation, r.provider == operator.ProviderOpenShift, r.pullSecrets))
	components = appendNotNil(components, Node(r.installation, r.provider, r.networkConfig))
	components = appendNotNil(components, KubeControllers(r.installation))
	return components
}

func appendNotNil(components []Component, c Component) []Component {
	if c != nil {
		components = append(components, c)
	}
	return components
}
