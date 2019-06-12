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

package installation

import (
	"fmt"
	"net/url"

	operator "github.com/tigera/operator/pkg/apis/operator/v1"
)

// validateCustomResource validates that the given custom resource is correct. This
// should be called after populating defaults and before rendering objects.
func validateCustomResource(instance *operator.Installation) error {
	if instance.Spec.Components.KubeProxy.Required {
		if len(instance.Spec.Components.KubeProxy.APIServer) == 0 {
			return fmt.Errorf("spec.apiServer required for kubeProxy installation")
		} else if _, err := url.ParseRequestURI(instance.Spec.Components.KubeProxy.APIServer); err != nil {
			return fmt.Errorf("spec.apiServer contains invalid domain string")
		}
	}
	return nil
}
