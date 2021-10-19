// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

// GetWindowsNodes returns Windows nodes, optionally filtering the list of nodes
// with the given filter functions.
package common

import (
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	corev1 "k8s.io/api/core/v1"
)

const (
	CalicoWindowsUpgradeResourceName = "calico-windows-upgrade"
	CalicoWindowsUpgradeScript       = "calico-upgrade.ps1"
	CalicoWindowsUpgradeVolumePath   = `c:\CalicoUpgrade`
	CalicoWindowsUpgradeScriptLabel  = "projectcalico.org/CalicoWindowsUpgradeScript"
	CalicoWindowsVersionAnnotation   = "projectcalico.org/CalicoWindowsVersion"
	CalicoWindowsUpgradeTaintKey     = "projectcalico.org/CalicoWindowsUpgrading"
)

func WindowsLatestVersionString(product operatorv1.ProductVariant) string {
	if product == operatorv1.Calico {
		return fmt.Sprintf("Calico-%v", components.CalicoRelease)
	} else {
		return fmt.Sprintf("Enterprise-%v", components.EnterpriseRelease)
	}
}

// GetWindowsNodeVersion gets the Windows node's version annotation and returns
// whether the annotation exists and its value.
func GetWindowsNodeVersion(n *corev1.Node) (bool, string) {
	ann, ok := n.Annotations[CalicoWindowsVersionAnnotation]
	if !ok {
		return false, ""
	}
	return true, ann
}
