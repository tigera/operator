// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

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
	"fmt"
	"strings"

	operatorv1 "github.com/tigera/operator/api/v1"
)

// validateCustomResource validates that the given custom resource is correct. This
// should be called after populating defaults and before rendering objects.
func validateCustomResource(instance *operatorv1.AmazonCloudIntegration) error {
	if instance == nil {
		return fmt.Errorf("no amazonCloudIntegration to validate, nil is not valid")
	}

	errMsgs := []string{}
	if len(instance.Spec.VPCS) == 0 {
		errMsgs = append(errMsgs, "missing spec.vpcs")
	}
	for _, x := range instance.Spec.VPCS {
		if x == "" {
			errMsgs = append(errMsgs, "empty spec.vpcs are not valid")
			break
		}
	}

	if instance.Spec.SQSURL == "" {
		errMsgs = append(errMsgs, "missing spec.sqsURL")
	}

	if instance.Spec.AWSRegion == "" {
		errMsgs = append(errMsgs, "missing spec.awsRegion")
	}

	if len(instance.Spec.NodeSecurityGroupIDs) == 0 {
		errMsgs = append(errMsgs, "missing spec.nodeSecurityGroupsIDs")
	}

	for _, x := range instance.Spec.NodeSecurityGroupIDs {
		if x == "" {
			errMsgs = append(errMsgs, "empty spec.nodeSecurityGroupIDs are not valid")
			break
		}
	}

	if instance.Spec.PodSecurityGroupID == "" {
		errMsgs = append(errMsgs, "missing spec.podSecurityGroupsID")
	}

	if instance.Spec.EnforcedSecurityGroupID == "" {
		errMsgs = append(errMsgs, "missing spec.enforcedSecurityGroupID")
	}

	if instance.Spec.TrustEnforcedSecurityGroupID == "" {
		errMsgs = append(errMsgs, "missing spec.trustEnforcedSecurityGroupID")
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("AmazonCloudIntegration invalid; %s", strings.Join(errMsgs, ", "))
	}

	return nil
}
