package openshift

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// IsOpenshift returns true if running on an openshift cluster, and false otherwise.
func IsOpenshift(cfg *rest.Config) (bool, error) {
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false, err
	}

	// Use the discovery client to determine if the openshift APIs exist.
	// If they do, it means we're on openshift.
	groups, err := clientset.Discovery().ServerGroups()
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
