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

package components

import (
	"fmt"

	operator "github.com/tigera/operator/api/v1"
)

// Image keys name the images a variant supplies its own build of. The key is the
// image's own name, so it selects an entry from CalicoImages or EnterpriseImages.
const (
	ImageKeyCalico     = "calico"
	ImageKeyNode       = "node"
	ImageKeyCNIPlugins = "third-party-cni-plugins"

	ImageKeyNodeWindows = "node-windows"
	ImageKeyCNIWindows  = "cni-windows"

	ImageKeyEnvoyGateway   = "envoy-gateway"
	ImageKeyEnvoyProxy     = "envoy-proxy"
	ImageKeyEnvoyRatelimit = "envoy-ratelimit"

	ImageKeyIstioPilot      = "istio-pilot"
	ImageKeyIstioInstallCNI = "istio-install-cni"
	ImageKeyIstioZTunnel    = "istio-ztunnel"
	ImageKeyIstioProxyv2    = "istio-proxyv2"
)

// ImageKeys is every key ImageFor answers, for the test that holds the keys and the
// component lists in sync.
var ImageKeys = []string{
	ImageKeyCalico, ImageKeyNode, ImageKeyCNIPlugins,
	ImageKeyNodeWindows, ImageKeyCNIWindows,
	ImageKeyEnvoyGateway, ImageKeyEnvoyProxy, ImageKeyEnvoyRatelimit,
	ImageKeyIstioPilot, ImageKeyIstioInstallCNI, ImageKeyIstioZTunnel, ImageKeyIstioProxyv2,
}

// ImageFor returns the image the given variant runs for key. A miss is an error rather
// than a fallback, since a Calico image on an Enterprise install is a bug.
func ImageFor(v operator.ProductVariant, key string) (Component, error) {
	list := CalicoImages
	if v.IsEnterprise() {
		list = EnterpriseImages
	}
	for _, c := range list {
		if c.Image == key {
			return c, nil
		}
	}
	return Component{}, fmt.Errorf("no image named %q for variant %s", key, v)
}

// ReferenceFor returns the fully qualified image the installation's variant runs for
// key, honoring the installation's registry and image path and any ImageSet.
func ReferenceFor(key string, in *operator.InstallationSpec, is *operator.ImageSet) (string, error) {
	c, err := ImageFor(in.Variant, key)
	if err != nil {
		return "", err
	}
	return GetReference(c, in.Registry, in.ImagePath, in.ImagePrefix, is)
}
