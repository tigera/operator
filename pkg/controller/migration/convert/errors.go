package convert

import "fmt"

// ErrIncompatibleCluster indicates that a config option was detected in the existing install
// which Operator does not support.
type ErrIncompatibleCluster struct {
	// err describes the error
	err string
	// fix explains what the user can do, if anything, to continue the migration.
	fix string
	// component identifies which component caused the problem.
	component string
}

func (e ErrIncompatibleCluster) Error() string {
	return fmt.Sprintf("%s. To fix it, %s on %s", e.err, e.fix, e.component)
}

const (
	ComponentCalicoNode      = "daemonset/calico-node"
	ComponentKubecontrollers = "deployment/calico-kube-controllers"
	ComponentTypha           = "deployment/calico-typha"
	ComponentCNIConfig       = "cni-config"
	ComponentIPPools         = "ippools"
)

var (
	FixFileFeatureRequest = "file a feature request with support.tigera.io to support clusters with your configuration"
	FixFileBugReport      = "file a bug report with support.tigera.io"
)

func ErrMissingHostPathVolume(component, volume, hostPath string) ErrIncompatibleCluster {
	return ErrIncompatibleCluster{
		err:       fmt.Sprintf("did not detect expected '%s' volume with hostPath '%s'", volume, hostPath),
		component: component,
		fix:       fmt.Sprintf("add the expected volume to %s", component),
	}
}

func ErrIncompatibleAnnotation(annotations map[string]string, component string) error {
	return ErrIncompatibleCluster{
		err:       fmt.Sprintf("unexpected annotation '%v'", annotations),
		component: component,
		fix:       "remove the annotation from the component",
	}
}

func ErrInvalidEnvVar(component, envVar, value, expectedValue string) ErrIncompatibleCluster {
	return ErrIncompatibleCluster{
		err:       fmt.Sprintf("%s=%s is not supported", envVar, value),
		component: component,
		fix:       fmt.Sprintf("remove the %s env var or set it to '%s'", envVar, expectedValue),
	}
}
