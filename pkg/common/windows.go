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
	"context"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	CalicoWindowsUpgradeResourceName = "calico-windows-upgrade"
	CalicoWindowsUpgradeScript       = "calico-upgrade.ps1"
	CalicoWindowsUpgradeVolumePath   = `c:\CalicoUpdate`
	CalicoWindowsUpgradeScriptLabel  = "projectcalico.org/CalicoWindowsUpgradeScript"
	CalicoWindowsVersionAnnotation   = "projectcalico.org/CalicoWindowsVersion"
)

func GetWindowsNodes(ctx context.Context, cli client.Client, filters ...func(node *corev1.Node) bool) ([]corev1.Node, error) {
	nodes := corev1.NodeList{}
	err := cli.List(context.Background(), &nodes, client.MatchingLabels{"kubernetes.io/os": "windows"})
	if err != nil {
		return nil, err
	}

	filteredNodes := []corev1.Node{}

	// Apply node filters, if any, and return only the nodes that match all
	// filters.
	// TODO: once we've upgraded to sigs.k8s.io/controller-runtime v0.9.0 we can
	// do this filtering server-side. See: https://github.com/kubernetes-sigs/controller-runtime/pull/1435
	for _, n := range nodes.Items {
		matchesAll := true

		for _, filter := range filters {
			if !filter(&n) {
				matchesAll = false
			}
		}

		if matchesAll {
			filteredNodes = append(filteredNodes, n)
		}
	}

	return filteredNodes, nil
}

// GetWindowsNodeVersion returns the node's Calico Windows version
func GetWindowsNodeVersion(n *corev1.Node) string {
	return n.Annotations[CalicoWindowsVersionAnnotation]
}
