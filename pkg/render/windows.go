// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

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
	"sigs.k8s.io/controller-runtime/pkg/client"

	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

func Windows(
	cfg *WindowsConfig,
) Component {
	return &windowsComponent{cfg: cfg}
}

type WindowsConfig struct {
	Installation *operatorv1.InstallationSpec
	Terminating  bool
}

type windowsComponent struct {
	cfg *WindowsConfig
}

func (c *windowsComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

func (c *windowsComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeWindows
}

func (c *windowsComponent) Objects() ([]client.Object, []client.Object) {
	objs := []client.Object{}

	if c.cfg.Terminating {
		return nil, objs
	}
	return objs, nil
}

func (c *windowsComponent) Ready() bool {
	return true
}
