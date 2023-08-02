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

// GetWindowsNodes returns Windows nodes, optionally filtering the list of nodes
// with the given filter functions.
package common

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	goversion "github.com/mcuadros/go-version"
)

func HasWindowsNodes(c client.Client) (bool, error) {
	nodes := corev1.NodeList{}
	err := c.List(context.Background(), &nodes, client.MatchingLabels{"kubernetes.io/os": "windows"})
	if err != nil {
		return false, err
	}

	return len(nodes.Items) > 0, nil
}

// HasWindowsNodesAndHPCSupport returns true if there is at least one node
// with Windows and containerd v1.7+ (the requirement for Calico Windows
// HPC Support)
func HasWindowsNodesAndHPCSupport(c client.Client) (bool, error) {
	nodes := corev1.NodeList{}
	err := c.List(context.Background(), &nodes, client.MatchingLabels{"kubernetes.io/os": "windows"})
	if err != nil {
		return false, err
	}

	for _, node := range nodes.Items {
		// ContainerRuntimeVersion will have the format "containerd://1.6.8" or "docker://2.3.4"
		splits := strings.Split(node.Status.NodeInfo.ContainerRuntimeVersion, "://")
		runtime := splits[0]
		ver := ""
		if len(splits) > 1 {
			ver = strings.TrimPrefix(splits[1], "v")
		}
		if runtime == "containerd" && goversion.CompareNormalized(ver, "1.6.0", ">=") {
			return true, nil
		}
	}

	return false, nil
}
