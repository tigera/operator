package controllers

import (
	"fmt"

	"github.com/tigera/operator/pkg/controller/options"

	ctrl "sigs.k8s.io/controller-runtime"
)

func addCloudControllersToManager(mgr ctrl.Manager, options options.AddOptions) error {
	if err := (&ImageAssuranceReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("ImageAssurance"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "ImageAssurance", err)
	}
	if err := (&RuntimeSecurityReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("RuntimeSecurity"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr, options); err != nil {
		return fmt.Errorf("failed to create controller %s: %v", "RuntimeSecurity", err)
	}
	return nil
}
