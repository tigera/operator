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

// Registry holds the extensions the operator runs with, for the one variant it
// resolved at startup. Every lookup returns something safe to call, so a nil
// Registry (the core operator) needs no guarding at the call site.
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

// RegisterController registers the extension for the named controller, replacing
// any prior one.
func (r *Registry) RegisterController(name controller.Name, ext ControllerExtension) {
	r.controllers[name] = ext
}

func (r *Registry) RegisterImage(component string, image components.Component) {
	r.images.Register(r.variant, component, image)
}

func (r *Registry) Controller(name controller.Name) ControllerExtension {
	if ext := r.controller(name); ext != nil {
		return ext
	}
	return noopExtension{}
}

func (r *Registry) Watcher(name controller.Name) Watcher {
	if w, ok := r.controller(name).(Watcher); ok {
		return w
	}
	return noopWatcher{}
}

func (r *Registry) FelixConfigDefaulter(name controller.Name) FelixConfigDefaulter {
	if d, ok := r.controller(name).(FelixConfigDefaulter); ok {
		return d
	}
	return noopFelixConfigDefaulter{}
}

func (r *Registry) Decorator() Decorator {
	if r == nil {
		return Decorator{}
	}
	return Decorator{variant: r.variant, modifiers: r.modifiers}
}

// Images returns the image override table, which render resolves through directly.
func (r *Registry) Images() *imageoverride.Overrides {
	if r == nil {
		return nil
	}
	return r.images
}

func (r *Registry) controller(name controller.Name) ControllerExtension {
	if r == nil {
		return nil
	}
	return r.controllers[name]
}

// RegisterModifier registers modify for the component that owns key. Cfg comes from
// the key, so a modifier written against a different component does not compile.
// Free function because Go has no generic methods.
func RegisterModifier[Cfg any](
	r *Registry,
	key render.ModifierKey[Cfg],
	modify func(ri render.Inputs, cfg Cfg, create, delete []client.Object) ([]client.Object, []client.Object),
) {
	r.modifiers[key.String()] = newDecorator(key, modify)
}
