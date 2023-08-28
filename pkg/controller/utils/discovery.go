// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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
	"strings"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/tigera/operator/api/v1"
)

var log = logf.Log.WithName("discovery")

// RequiresTigeraSecure determines if the configuration requires we start the tigera secure
// controllers.
func RequiresTigeraSecure(cfg *rest.Config) (bool, error) {
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, err
	}

	// Use the discovery client to determine if the tigera secure specific APIs exist.
	resources, err := clientset.Discovery().ServerResourcesForGroupVersion("operator.tigera.io/v1")
	if err != nil {
		return false, err
	}
	for _, r := range resources.APIResources {
		switch r.Kind {
		case "LogCollector":
			fallthrough
		case "LogStorage":
			fallthrough
		case "AmazonCloudIntegration":
			fallthrough
		case "Compliance":
			fallthrough
		case "IntrusionDetection":
			fallthrough
		case "ApplicationLayer":
			fallthrough
		case "Monitor":
			fallthrough
		case "ManagementCluster":
			fallthrough
		case "EgressGateway":
			fallthrough
		case "ManagementClusterConnection":
			return true, nil
		}
	}
	return false, nil
}

// RequiresAmazonController determines if the configuration requires we start the aws
// controllers.
func RequiresAmazonController(cfg *rest.Config) (bool, error) {
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, err
	}

	// Use the discovery client to determine if the amazoncloudintegration APIs exist.
	resources, err := clientset.Discovery().ServerResourcesForGroupVersion("operator.tigera.io/v1")
	if err != nil {
		return false, err
	}
	for _, r := range resources.APIResources {
		if r.Kind == "AmazonCloudIntegration" {
			return true, nil
		}
	}
	return false, nil
}

func MultiTenant(ctx context.Context, c kubernetes.Interface) (bool, error) {
	resources, err := c.Discovery().ServerResourcesForGroupVersion("operator.tigera.io/v1")
	if err != nil {
		return false, err
	}
	for _, res := range resources.APIResources {
		if strings.EqualFold(res.Kind, "Manager") {
			// If the Manager is namespaced, it means we're operating in multi-tenant mode.
			return res.Namespaced, nil
		}
	}

	// Default to single-tenant.
	return false, nil
}

func AutoDiscoverProvider(ctx context.Context, clientset kubernetes.Interface) (operatorv1.Provider, error) {
	// First, try to determine the platform based on the present API groups.
	if platform, err := autodetectFromGroup(clientset); err != nil {
		return operatorv1.ProviderNone, fmt.Errorf("Failed to check provider based on API groups: %s", err)
	} else if platform != operatorv1.ProviderNone {
		// We detected a platform. Use it.
		return platform, nil
	}

	// We failed to determine the platform based on API groups. Some platforms can be detected in other ways, though.
	if dockeree, err := isDockerEE(ctx, clientset); err != nil {
		return operatorv1.ProviderNone, fmt.Errorf("Failed to check if Docker EE is the provider: %s", err)
	} else if dockeree {
		return operatorv1.ProviderDockerEE, nil
	}

	// We failed to determine the platform based on API groups. Some platforms can be detected in other ways, though.
	if eks, err := isEKS(ctx, clientset); err != nil {
		return operatorv1.ProviderNone, fmt.Errorf("Failed to check if EKS is the provider: %s", err)
	} else if eks {
		return operatorv1.ProviderEKS, nil
	}

	// Attempt to detect RKE Version 2, which also cannot be done via API groups.
	if rke2, err := isRKE2(ctx, clientset); err != nil {
		return operatorv1.ProviderNone, fmt.Errorf("Failed to check if RKE2 is the provider: %s", err)
	} else if rke2 {
		return operatorv1.ProviderRKE2, nil
	}

	// Couldn't detect any specific platform.
	return operatorv1.ProviderNone, nil
}

// autodetectFromGroup auto detects the platform based on the API groups that are present.
func autodetectFromGroup(c kubernetes.Interface) (operatorv1.Provider, error) {
	groups, err := c.Discovery().ServerGroups()
	if err != nil {
		return operatorv1.ProviderNone, err
	}
	for _, g := range groups.Groups {
		if g.Name == "config.openshift.io" {
			// Running on OpenShift.
			return operatorv1.ProviderOpenShift, nil
		}

		if g.Name == "networking.gke.io" {
			// Running on GKE.
			return operatorv1.ProviderGKE, nil
		}
	}
	return operatorv1.ProviderNone, nil
}

// isDockerEE returns true if running on a Docker Enterprise cluster, and false otherwise.
// Docker EE doesn't have any provider-specific API groups, so we need to use a different approach than
// we use for other platforms in autodetectFromGroup.
func isDockerEE(ctx context.Context, c kubernetes.Interface) (bool, error) {
	masterNodes, err := c.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/master"})
	if err != nil {
		return false, err
	}
	for _, n := range masterNodes.Items {
		for l := range n.Labels {
			if strings.HasPrefix(l, "com.docker.ucp") {
				return true, nil
			}
		}
	}
	return false, nil
}

// isEKS returns true if running on an EKS cluster, and false otherwise.
// EKS doesn't have any provider-specific API groups, so we need to use a different approach than
// we use for other platforms in autodetectFromGroup.
func isEKS(ctx context.Context, c kubernetes.Interface) (bool, error) {
	// This looks for a configmap that is used in EKS clusters for enabling access to EKS clusters
	// https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html
	_, err := c.CoreV1().ConfigMaps("kube-system").Get(ctx, "aws-auth", metav1.GetOptions{})
	if err == nil {
		return true, nil
	} else if !kerrors.IsNotFound(err) {
		return false, err
	}

	// This is a config map that that use to be present in EKS cluster but now seems to be deprecated.
	// We'll keep this detection so we ensure we detect EKS in older clusters that have this.
	_, err = c.CoreV1().ConfigMaps("kube-system").Get(ctx, "eks-certificates-controller", metav1.GetOptions{})
	if err == nil {
		return true, nil
	} else if !kerrors.IsNotFound(err) {
		return false, err
	}

	// We'll check the labels on the kube-dns service if it exists and if we find the seemingly EKS
	// specific label then we'll assume EKS.
	dnsService, err := c.CoreV1().Services("kube-system").Get(ctx, "kube-dns", metav1.GetOptions{})
	if err == nil {
		if dnsService != nil {
			for key := range dnsService.Labels {
				if key == "eks.amazonaws.com/component" {
					return true, nil
				}
			}
		}
	} else if !kerrors.IsNotFound(err) {
		return false, err
	}

	return false, nil
}

// isRKE2 returns true if running on an RKE2 cluster, and false otherwise.
// While the presence of Rancher can be determined based on API Groups, it's important to
// differentiate between versions, which requires another approach. In this case,
// the presence of an "rke2" configmap in kube-system namespace is used.
func isRKE2(ctx context.Context, c kubernetes.Interface) (bool, error) {
	cm, err := c.CoreV1().ConfigMaps("kube-system").Get(ctx, "rke2", metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return (cm != nil), nil
}

// SupportsPodSecurityPolicies returns true if the cluster contains the policy/v1beta1 PodSecurityPolicy API,
// and false otherwise. This API is scheduled to be removed in Kubernetes v1.25, but should still be used
// in earlier Kubernetes versions.
func SupportsPodSecurityPolicies(c kubernetes.Interface) (bool, error) {
	resources, err := c.Discovery().ServerResourcesForGroupVersion("policy/v1beta1")
	if err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	for _, r := range resources.APIResources {
		if r.Kind == "PodSecurityPolicy" {
			return true, nil
		}
	}
	return false, nil
}
