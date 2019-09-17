package utils

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
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

func AutoDiscoverProvider(cfg *rest.Config) (operatorv1.Provider, error) {
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return operatorv1.ProviderNone, fmt.Errorf("Failed to get client for auto provider discovery: %v", err)
	}

	// Determine if we're running on openshift.
	openshift, err := isOpenshift(clientset)
	if err != nil {
		return operatorv1.ProviderNone, fmt.Errorf("Failed to discover OpenShift API groups: %v", err)
	} else if openshift {
		return operatorv1.ProviderOpenShift, nil
	}
	// Determine if we're running on Docker Enterprise.
	dockeree, err := isDockerEE(clientset)
	if err != nil {
		return operatorv1.ProviderNone, fmt.Errorf("Failed to check if Docker EE is the provider: %v", err)
	} else if dockeree {
		return operatorv1.ProviderDockerEE, nil
	}
	return operatorv1.ProviderNone, nil
}

// isOpenshift returns true if running on an openshift cluster, and false otherwise.
func isOpenshift(c *kubernetes.Clientset) (bool, error) {
	// Use the discovery client to determine if the openshift APIs exist.
	// If they do, it means we're on openshift.
	groups, err := c.Discovery().ServerGroups()
	if err != nil {
		return false, err
	}
	for _, g := range groups.Groups {
		if g.Name == "config.openshift.io" {
			return true, nil
		}
	}
	return false, nil
}

// isDockerEE returns true if running on a Docker Enterprise cluster, and false otherwise.
func isDockerEE(c *kubernetes.Clientset) (bool, error) {
	masterNodes, err := c.CoreV1().Nodes().List(metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/master"})
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
