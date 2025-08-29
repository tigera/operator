// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	KubeProxyInstanceKey = client.ObjectKey{Name: "kube-proxy", Namespace: "kube-system"}
)

// ValidateDaemonSetManaged checks whether the DaemonSet is managed by an external tool,
// based on common labels or annotations typically added by automation.
func ValidateDaemonSetManaged(ds *appsv1.DaemonSet) error {
	if len(ds.Labels) == 0 && len(ds.Annotations) == 0 {
		return nil
	}

	// Kubernetes well-known labels
	if _, ok := ds.Labels["app.kubernetes.io/managed-by"]; ok {
		return fmt.Errorf("DaemonSet is likely managed by: %s", ds.Labels["app.kubernetes.io/managed-by"])
	}
	if _, ok := ds.Labels["addonmanager.kubernetes.io/mode"]; ok {
		return fmt.Errorf("DaemonSet is likely managed by another source due to the label 'addonmanager.kubernetes.io/mode: %s'", ds.Labels["addonmanager.kubernetes.io/mode"])
	}

	// Check for GitOps tools
	if _, ok := ds.Annotations["argocd.argoproj.io/tracking-id"]; ok {
		return fmt.Errorf("DaemonSet is likely managed by another source due to the label 'argocd.argoproj.io/tracking-id: %s'", ds.Annotations["argocd.argoproj.io/tracking-id"])
	}

	return nil
}

func GetManageableKubeProxy(ctx context.Context, c client.Client) (*appsv1.DaemonSet, error) {
	kubeProxyDS := &appsv1.DaemonSet{}
	err := c.Get(ctx, KubeProxyInstanceKey, kubeProxyDS)
	if err != nil {
		return nil, fmt.Errorf("failed to get kube-proxy: %w", err)
	}

	err = ValidateDaemonSetManaged(kubeProxyDS)
	if err != nil {
		return nil, err
	}

	return kubeProxyDS, nil
}
