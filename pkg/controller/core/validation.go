package core

import (
	"fmt"
	"net/url"

	operatorv1alpha1 "github.com/tigera/operator/pkg/apis/operator/v1alpha1"
)

// validateCustomResource validates that the given custom resource is correct. This
// should be called after populating defaults and before rendering objects.
func validateCustomResource(instance *operatorv1alpha1.Core) error {
	if instance.Spec.Components.KubeProxy.Required {
		if len(instance.Spec.Components.KubeProxy.APIServer) == 0 {
			return fmt.Errorf("spec.components.kubeProxy.apiServer required for kubeProxy installation")
		} else if _, err := url.ParseRequestURI(instance.Spec.Components.KubeProxy.APIServer); err != nil {
			return fmt.Errorf("spec.components.kubeProxy.apiServer contains invalid domain string")
		}
	}

	if instance.Spec.Components.APIServer != nil {
		// Both the key and the certificate either be specified or not at all.
		certEmpty := len(instance.Spec.Components.APIServer.TLS.Certificate) == 0
		keyEmpty := len(instance.Spec.Components.APIServer.TLS.Key) == 0
		if (certEmpty && !keyEmpty) || (!certEmpty && keyEmpty) {
			return fmt.Errorf("spec.components.apiServer.tls.certificate or key is missing")
		}
	}
	return nil
}
