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
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/api/v1"
)

type BPFBootstrap struct {
	KubeProxyDs         *appsv1.DaemonSet
	K8sService          *corev1.Service
	K8sServiceEndpoints *discoveryv1.EndpointSliceList
}

// BPFBootstrapRequirements checks whether the BPF auto-bootstrap requirements are met.
// If so, it retrieves the kube-proxy DaemonSet, the Kubernetes service, and its EndpointSlices, returning them in a BPFBootstrap struct.
// If it's not possible to retrieve any of these resources, it returns an error.
func BPFBootstrapRequirements(c client.Client, ctx context.Context, install *operator.InstallationSpec) (*BPFBootstrap, error) {
	// If BPFNetworkBootstrap or KubeProxyManagement are not Enabled, skip further processing.
	if !install.BPFNetworkBootstrapEnabled() && !install.KubeProxyManagementEnabled() {
		return nil, nil
	}

	// 1. kubernetes service endpoint shouldn't be defined by kubernetes-service-endpoints ConfigMap.
	_, err := GetK8sServiceEndPoint(c)
	if err == nil {
		return nil, fmt.Errorf("kubernetes service endpoint is defined by the kubernetes-service-endpoints ConfigMap.")
	}

	bpfBootstrapReq := &BPFBootstrap{}
	// 2. Try to retrieve the kube-proxy DaemonSet.
	ds := &appsv1.DaemonSet{}
	err = c.Get(ctx, types.NamespacedName{Namespace: KubeProxyNamespace, Name: KubeProxyDaemonSetName}, ds)
	if err != nil {
		return nil, fmt.Errorf("failed to get kube-proxy: %w", err)
	}

	// 3. Validate that the kube-proxy DaemonSet is not managed by an external tool.
	if err = validateDaemonSetManaged(ds); err != nil {
		return nil, fmt.Errorf("failed to validate kube-proxy DaemonSet: %w", err)
	}
	bpfBootstrapReq.KubeProxyDs = ds

	// 4. Try to retrieve kubernetes service.
	service := &corev1.Service{}
	err = c.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kubernetes"}, service)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes service: %w", err)
	}
	bpfBootstrapReq.K8sService = service

	// 5. Try to retrieve kubernetes service endpoint slices. If the cluster is dual-stack, there should be at least one EndpointSlice for each address type.
	endpointSlice := &discoveryv1.EndpointSliceList{}
	err = c.List(ctx, endpointSlice, client.InNamespace("default"), client.MatchingLabels{"kubernetes.io/service-name": "kubernetes"})
	if err != nil || len(endpointSlice.Items) == 0 {
		return nil, fmt.Errorf("failed to get kubernetes endpoint slices: %w", err)
	}
	bpfBootstrapReq.K8sServiceEndpoints = endpointSlice

	return bpfBootstrapReq, nil
}

// validateDaemonSetManaged checks whether the DaemonSet is managed by an external tool,
// based on common labels or annotations typically added by automation.
func validateDaemonSetManaged(ds *appsv1.DaemonSet) error {
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
