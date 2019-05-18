package core

import (
	"fmt"

	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
)

// validateCustomResource validates that the given custom resource is correct. This
// should be called after populating defaults and before rendering objects.
func validateCustomResource(instance *operatorv1alpha1.Core) error {
	if instance.Spec.RunKubeProxy && len(instance.Spec.APIServer) == 0 {
		return fmt.Errorf("spec.apiServer required for kubeProxy installation")
	}
	return nil
}
