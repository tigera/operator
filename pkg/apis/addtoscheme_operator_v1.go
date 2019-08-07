package apis

import (
	configv1 "github.com/openshift/api/config/v1"
	ocsv1 "github.com/openshift/api/security/v1"
	tigera "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	v1 "github.com/tigera/operator/pkg/apis/operator/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	aggregator "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/scheme"
)

func init() {
	// Register the types with the Scheme so the components can map objects to GroupVersionKinds and back
	AddToSchemes = append(AddToSchemes, v1.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, operator.SchemeBuilder.AddToScheme)
	AddToSchemes = append(AddToSchemes, configv1.Install)
	AddToSchemes = append(AddToSchemes, aggregator.AddToScheme)
	AddToSchemes = append(AddToSchemes, apiextensions.AddToScheme)
	AddToSchemes = append(AddToSchemes, tigera.AddToScheme)
	AddToSchemes = append(AddToSchemes, ocsv1.AddToScheme)
}
