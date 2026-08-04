// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package extensions

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller"
	"github.com/tigera/operator/pkg/imageoverride"
	"github.com/tigera/operator/pkg/render"
)

// Registry holds the extensions the operator runs with. The process resolves its
// variant at startup and never changes it, so an extension build (e.g. Calico
// Enterprise) constructs a Registry for that one variant and hands it in through
// options.ControllerOptions; the core operator hands in nil.
//
// Callers look up what they need once, at construction, and get back something
// safe to call: a lookup that finds nothing yields a no-op rather than nil, so
// neither the core operator's nil Registry nor a variant that extends only some
// controllers needs guarding at the call site.
type Registry struct {
	variant     operatorv1.ProductVariant
	controllers map[controller.Name]ControllerExtension
	modifiers   map[string]decorator
	images      *imageoverride.Overrides
}

// NewRegistry returns an empty Registry for the variant the operator is running as.
func NewRegistry(variant operatorv1.ProductVariant) *Registry {
	return &Registry{
		variant:     variant,
		controllers: map[controller.Name]ControllerExtension{},
		modifiers:   map[string]decorator{},
		images:      imageoverride.New(),
	}
}

// RegisterController registers the controller-side extension for the named
// controller. A controller has at most one; registering replaces any prior one.
func (r *Registry) RegisterController(name controller.Name, ext ControllerExtension) {
	r.controllers[name] = ext
}

// RegisterImage registers an image override for the named component.
func (r *Registry) RegisterImage(component string, image components.Component) {
	r.images.Register(r.variant, component, image)
}

// Controller returns the extension for the named controller, or a no-op when none
// is registered.
func (r *Registry) Controller(name controller.Name) ControllerExtension {
	if ext := r.controller(name); ext != nil {
		return ext
	}
	return noopExtension{}
}

// Watcher returns the named controller's extension as a Watcher, or a no-op when
// no extension is registered or it declares no watches.
func (r *Registry) Watcher(name controller.Name) Watcher {
	if w, ok := r.controller(name).(Watcher); ok {
		return w
	}
	return noopWatcher{}
}

// FelixConfigDefaulter returns the named controller's extension as a
// FelixConfigDefaulter, or a no-op when no extension is registered or it defaults
// no FelixConfiguration fields.
func (r *Registry) FelixConfigDefaulter(name controller.Name) FelixConfigDefaulter {
	if d, ok := r.controller(name).(FelixConfigDefaulter); ok {
		return d
	}
	return noopFelixConfigDefaulter{}
}

// Decorator returns the decorator that applies the registered component
// modifiers, for handing to a component handler.
func (r *Registry) Decorator() Decorator {
	if r == nil {
		return Decorator{}
	}
	return Decorator{modifiers: r.modifiers}
}

// Images returns the image override table. The render package resolves a
// component's image through it directly, so render need not import extensions.
func (r *Registry) Images() *imageoverride.Overrides {
	if r == nil {
		return nil
	}
	return r.images
}

// controller looks up the raw registration, nil when there is none.
func (r *Registry) controller(name controller.Name) ControllerExtension {
	if r == nil {
		return nil
	}
	return r.controllers[name]
}

// RegisterModifier registers modify for the component that owns key. Cfg comes from
// the key, not from modify, so a modifier written against a different component does
// not compile. It asserts the component's inputs to Cfg once, here, so the modifier
// body needs no assertion. Free function because Go has no generic methods.
func RegisterModifier[Cfg any](
	r *Registry,
	key render.ModifierKey[Cfg],
	modify func(ri render.Inputs, cfg Cfg, create, delete []client.Object) ([]client.Object, []client.Object),
) {
	r.modifiers[key.String()] = newDecorator(key, modify)
}
