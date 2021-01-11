// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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
	"strconv"
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
		if r.Kind == "APIServer" {
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

	// Couldn't detect any specific platform.
	return operatorv1.ProviderNone, nil
}

type VersionInfo struct {
	Minor int
}

// GetKubernetesVersion gets and processes the verison reported by k8s-apiserver.
// If the version is unrecognizable, nil is returned.
func GetKubernetesVersion(ctx context.Context, clientset kubernetes.Interface) (*VersionInfo, error) {
	v, err := clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to check k8s version: %v", err)
	}

	if v.Major != "1" {
		return nil, nil
	}

	// filter out a proceeding '+' from the minor version since openshift
	// includes that.
	minor, err := strconv.Atoi(strings.TrimSuffix(v.Minor, "+"))
	if err != nil {
		return nil, nil
	}

	return &VersionInfo{
		Minor: minor,
	}, nil
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
		for l, _ := range n.Labels {
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
	cm, err := c.CoreV1().ConfigMaps("kube-system").Get(ctx, "eks-certificates-controller", metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return (cm != nil), nil
}
