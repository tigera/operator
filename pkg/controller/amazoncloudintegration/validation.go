// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

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

package amazoncloudintegration

import (
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

// validateCustomResource validates that the given custom resource is correct. This
// should be called after populating defaults and before rendering objects.
func validateCustomResource(instance *operatorv1.AmazonCloudIntegration) error {

	// TODO: Do some validation

	//if instance.Spec.Variant == operatorv1.Calico {
	//	// Validation specific to Calico.
	//	if instance.Spec.ClusterManagementType != "" {
	//		return fmt.Errorf("clusterManagementType must not be set for variant 'Calico'")
	//	}
	//}

	return nil
}
