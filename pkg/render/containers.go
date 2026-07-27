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

package render

import (
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

// Container returns the named container in spec, searching regular containers
// before init containers. The returned pointer aliases spec, so mutating it
// mutates the pod.
//
// Variant modifiers layer onto containers this package renders, and they can only
// find them by name. Picking them out of the PodSpec directly means matching a
// name render chose with nothing tying the two together: rename the container and
// the modifier keeps compiling and silently stops matching. Going through here
// keeps the lookup next to the names, and makes a miss loud - a modifier asking
// for a container the component no longer renders is a bug on one side or the
// other, not something to skip over quietly.
func Container(spec *corev1.PodSpec, name string) (*corev1.Container, bool) {
	for i := range spec.Containers {
		if spec.Containers[i].Name == name {
			return &spec.Containers[i], true
		}
	}
	for i := range spec.InitContainers {
		if spec.InitContainers[i].Name == name {
			return &spec.InitContainers[i], true
		}
	}
	logrus.Errorf("BUG: no container named %q to modify; leaving it alone", name)
	return nil, false
}

// Containers returns the named containers in spec, in the order named, skipping
// (and logging) any that are absent. A partial match is as loud as no match.
func Containers(spec *corev1.PodSpec, names ...string) []*corev1.Container {
	found := make([]*corev1.Container, 0, len(names))
	for _, name := range names {
		if c, ok := Container(spec, name); ok {
			found = append(found, c)
		}
	}
	return found
}
