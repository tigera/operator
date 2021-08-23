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
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
)

func Secrets(secrets []*corev1.Secret) Component {
	return &secretsComponent{secrets: secrets}
}

type secretsComponent struct {
	secrets []*corev1.Secret
}

func (c *secretsComponent) ResolveImages(is *operatorv1.ImageSet) error {
	// No images to resolve
	return nil
}

func (c *secretsComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}

func (c *secretsComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{}
	for _, s := range c.secrets {
		objs = append(objs, s)
	}
	return objs, nil
}

func (c *secretsComponent) Ready() bool {
	return true
}
