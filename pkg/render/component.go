// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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
	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Component interface {
	// ResolveImages should call components.GetReference for all images that the Component
	// needs, passing 'is' to the GetReference call and if there are any errors those
	// are returned. It is valid to pass nil for 'is' as GetReference accepts the value.
	// ResolveImages must be called before Objects is called for the component.
	ResolveImages(is *operatorv1.ImageSet) error

	// Objects returns the lists of objects in this component that should be created and/or deleted during
	// rendering.
	Objects() (objsToCreate, objsToDelete []client.Object)

	// Ready returns true if the component is ready to be created.
	Ready() bool

	// SupportedOSTypes returns operating systems that is supported of the components returned by the Objects() function.
	// The "componentHandler" converts the returned OSTypes to a node selectors for the "kubernetes.io/os" label on client.Objects
	// that create pods. Return OSTypeAny means that no node selector should be set for the "kubernetes.io/os" label.
	SupportedOSType() rmeta.OSType
}

// Extensible is implemented by components that expose extension points. The
// componentHandler uses ModifierKey() to look up registered modifiers.
// Components without extensions need not implement it. The method name is
// deliberately specific (not a generic Name()) so an unrelated method can't
// make a component modifier-eligible by accident.
type Extensible interface {
	ModifierKey() string
}

// ExtensionInputsProvider is a companion to Extensible. A component implements it
// to hand its modifier the inputs only that component can supply - config its own
// controller gathered, such as a keypair the controller created. A component with
// nothing to hand over still implements it and returns its empty inputs type, so
// that every extension point has a type to key on. extensions.Modify asserts the
// returned value to the key's config type, so the modifier body needs no assertion.
type ExtensionInputsProvider interface {
	ExtensionInputs() any
}

// ModifierKey names a component's extension point and pins the type of the inputs
// its modifier receives, which is whatever that component's ExtensionInputs
// returns.
//
// name is unexported, so keys can only be declared here, next to the component
// they belong to. Registration takes a key rather than a bare name, and
// extensions.Modify infers Cfg from the key rather than from the modifier - that
// is what lets the compiler reject a modifier written against a different
// component.
type ModifierKey[Cfg any] struct {
	name string
}

// String returns the registry key. The modifier registry holds every component's
// modifier together, so it is keyed by this rather than by the typed key.
func (k ModifierKey[Cfg]) String() string {
	return k.name
}

// Extension inputs for the components whose modifiers need nothing beyond Inputs.
// They are empty today and exist so each extension point has a distinct type -
// sharing one empty type between components would let the compiler accept a
// modifier registered against the wrong one. A component that later needs to hand
// something to its modifier gains a field here and no signature changes.
type (
	TyphaExtensionInputs                 struct{}
	NodeExtensionInputs                  struct{}
	WindowsExtensionInputs               struct{}
	KubeControllersExtensionInputs       struct{}
	KubeControllersPolicyExtensionInputs struct{}
)

// The extension point of each component that exposes one. A component's
// ModifierKey returns its key from here and the variant registers against that
// same key, so the two cannot drift onto different components without failing to
// compile.
var (
	TyphaKey                 = ModifierKey[TyphaExtensionInputs]{ComponentNameTypha}
	NodeKey                  = ModifierKey[NodeExtensionInputs]{ComponentNameNode}
	WindowsKey               = ModifierKey[WindowsExtensionInputs]{ComponentNameWindows}
	KubeControllersKey       = ModifierKey[KubeControllersExtensionInputs]{ComponentNameKubeControllers}
	KubeControllersPolicyKey = ModifierKey[KubeControllersPolicyExtensionInputs]{ComponentNameKubeControllersPolicy}
)

// Component names. Those that key an extension point are wrapped by the keys
// above; the rest key image overrides, which carry no inputs type.
const (
	ComponentNameTypha = "typha"
	ComponentNameNode  = "node"

	// ComponentNameCNIPlugins keys the upstream CNI plugins image. The node
	// component renders the cni-plugins init container, so the image resolves
	// through its own override key.
	ComponentNameCNIPlugins = "cni-plugins"

	// ComponentNameWindows keys the windows daemonset modifier. The two windows
	// images resolve through their own override keys, since one component renders
	// both.
	ComponentNameWindows        = "windows"
	ComponentNameWindowsNodeImg = "windows-node-image"
	ComponentNameWindowsCNIImg  = "windows-cni-image"

	// ComponentNameKubeControllers keys the calico-kube-controllers modifier. The
	// es-calico-kube-controllers deployment shares the component type but leaves
	// its modifier key empty, so it is not decorated.
	ComponentNameKubeControllers = "kube-controllers"

	// ComponentNameKubeControllersPolicy keys the calico-kube-controllers network
	// policy modifier (the WAF admission webhook ingress rule).
	ComponentNameKubeControllersPolicy = "kube-controllers-policy"
)
