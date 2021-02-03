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
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

func ConfigMaps(cms []*corev1.ConfigMap) Component {
	return &configMapComponent{configMaps: cms}
}

type configMapComponent struct {
	configMaps []*corev1.ConfigMap
}

func (c *configMapComponent) ResolveImages(is *operator.ImageSet) error {
	// No images to resolve
	return nil
}

func (c *configMapComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

func (c *configMapComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{}
	for _, cm := range c.configMaps {
		objs = append(objs, cm)
	}
	return objs, nil
}

func (c *configMapComponent) Ready() bool {
	return true
}
