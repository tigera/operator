package core

import (
	"fmt"
	"net/url"

	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
)

// validateCustomResource validates that the given custom resource is correct. This
// should be called after populating defaults and before rendering objects.
func validateCustomResource(instance *operatorv1alpha1.Core) error {
	if instance.Spec.KubeProxy.Required {
		if len(instance.Spec.KubeProxy.APIServer) == 0 {
			return fmt.Errorf("spec.apiServer required for kubeProxy installation")
		} else if _, err := url.ParseRequestURI(instance.Spec.KubeProxy.APIServer); err != nil {
			return fmt.Errorf("spec.apiServer contains invalid domain string")
		}
	}
	return nil
}
