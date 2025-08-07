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
	"errors"
	"fmt"
	"net"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operator "github.com/tigera/operator/api/v1"
)

type BPFAutoBootstrap struct {
	KubeProxyDs         *appsv1.DaemonSet
	K8sService          *corev1.Service
	K8sServiceEndpoints *discoveryv1.EndpointSliceList
}

// BPFAutoInstallRequirements checks whether the BPF auto-bootstrap requirements are met.
// If so, it retrieves the kube-proxy DaemonSet, the Kubernetes service, and its EndpointSlices, returning them in a BPFAutoBootstrap struct.
// If it's not possible to retrieve any of these resources, it returns an error.
func BPFAutoInstallRequirements(c client.Client, ctx context.Context, install *operator.InstallationSpec) (*BPFAutoBootstrap, error) {
	// 1. If BPFInstallMode is not set to Auto, skip further processing.
	if !install.BPFInstallModeAuto() {
		return nil, nil
	}

	// 2. CNI plugin is Calico.
	if install.CNI.Type != operator.PluginCalico {
		return nil, fmt.Errorf("the CNI plugin is not Calico in Installation CR")
	}

	bpfBootstrapReq := &BPFAutoBootstrap{}
	// 3. Try to retrieve the kube-proxy DaemonSet.
	ds := &appsv1.DaemonSet{}
	err := c.Get(ctx, types.NamespacedName{Namespace: KubeProxyNamespace, Name: KubeProxyDaemonSetName}, ds)
	if err != nil {
		return nil, fmt.Errorf("failed to get kube-proxy: %w", err)
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

	if err = validateIpFamilyConsistency(service, endpointSlice); err != nil {
		return nil, err
	}

	return bpfBootstrapReq, nil
}

// validateIpFamilyConsistency checks whether the service and EndpointSliceList have consistent IP address families.
func validateIpFamilyConsistency(service *corev1.Service, endpointSliceList *discoveryv1.EndpointSliceList) error {

	// Validating EndpointSlice IPs.
	epHasIPv4, epHasIPv6 := false, false
nestedLoop:
	for _, slice := range endpointSliceList.Items {
		for _, endpoint := range slice.Endpoints {
			for _, addr := range endpoint.Addresses {
				ip := net.ParseIP(addr)
				if ip == nil {
					return fmt.Errorf("Endpoint has an invalid IP: %s", addr)
				}

				if ip.To4() != nil {
					epHasIPv4 = true
				} else {
					epHasIPv6 = true
				}

				if epHasIPv4 && epHasIPv6 {
					break nestedLoop
				}
			}
		}
	}

	// Validating Service IPs.
	svcHasIPv4, svcHasIPv6 := false, false
	ips := service.Spec.ClusterIPs
	if len(ips) == 0 && service.Spec.ClusterIP != "" {
		ips = []string{service.Spec.ClusterIP}
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("service has an invalid IP: %s", ipStr)
		}

		if ip.To4() != nil {
			svcHasIPv4 = true
		} else {
			svcHasIPv6 = true
		}
	}

	var errV4, errV6 error
	if svcHasIPv4 != epHasIPv4 {
		errV4 = fmt.Errorf("service and EndpointSlice have inconsistent IPv4 configuration")
	}
	if svcHasIPv6 != epHasIPv6 {
		errV6 = fmt.Errorf("service and EndpointSlice have inconsistent IPv6 configuration")
	}

	return errors.Join(errV4, errV6)
}
