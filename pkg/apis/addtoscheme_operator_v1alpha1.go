package apis

import (
	configv1 "github.com/openshift/api/config/v1"
	"github.com/tigera/operator/pkg/apis/operator/v1alpha1"
)

func init() {
	// Register the types with the Scheme so the components can map objects to GroupVersionKinds and back
	AddToSchemes = append(AddToSchemes, v1alpha1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, configv1.Install)
}
