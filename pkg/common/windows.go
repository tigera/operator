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

var (
	// This taint is applied to nodes upgrading Calico Windows.
	CalicoWindowsUpgradingTaint = &corev1.Taint{
		Key:    CalicoWindowsUpgradeTaintKey,
		Effect: corev1.TaintEffectNoSchedule,
	}
)

const (
	CalicoWindowsUpgradeResourceName    = "calico-windows-upgrade"
	CalicoWindowsUpgradeVolumePath      = `c:\CalicoUpgrade`
	CalicoWindowsUpgradeLabel           = "projectcalico.org/windows-upgrade"
	CalicoWindowsUpgradeLabelInProgress = "in-progress"
	CalicoVersionAnnotation             = "projectcalico.org/version"
	CalicoVariantAnnotation             = "projectcalico.org/variant"
	CalicoWindowsUpgradeTaintKey        = "projectcalico.org/windows-upgrade"
)

func WindowsLatestVersionString(product operatorv1.ProductVariant) string {
	if product == operatorv1.Calico {
		return fmt.Sprintf("Calico-%v", components.CalicoRelease)
	} else {
		return fmt.Sprintf("Enterprise-%v", components.EnterpriseRelease)
	}
}

// GetNodeVariantAndVersion gets the node's variant and version annotation
// values and returns whether both annotations exist.
func GetNodeVariantAndVersion(n *corev1.Node) (bool, operatorv1.ProductVariant, string) {
	variant, ok := n.Annotations[CalicoVariantAnnotation]
	if !ok {
		return false, "", ""
	}
	version, ok := n.Annotations[CalicoVersionAnnotation]
	if !ok {
		return false, "", ""
	}

	return true, operatorv1.ProductVariant(variant), version
}
