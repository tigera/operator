package meta

import (
	"crypto/sha1"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// This type helps ensure that we only use defined os types
type OSType string

const (
	DefaultCertificateDuration = 100 * 365 * 24 * time.Hour

	OSTypeAny     OSType = "any"
	OSTypeLinux   OSType = "linux"
	OSTypeWindows OSType = "windows"

	// The name prefix used for the CA issuer, which is used for self-signed
	// certificates issued for operator-managed certificates.
	// NOTE: Do not change this field since we use this value to identify
	// certificates managed by this operator.
	TigeraOperatorCAIssuerPrefix = "tigera-operator-signer"
)

var (
	// TolerateMaster allows pod to be scheduled on master nodes
	TolerateMaster = corev1.Toleration{
		Key:    "node-role.kubernetes.io/master",
		Effect: corev1.TaintEffectNoSchedule,
	}

	// TolerateCriticalAddonsOnly allows pods to be rescheduled while the node is in "critical add-ons only" mode.
	TolerateCriticalAddonsOnly = corev1.Toleration{
		Key:      "CriticalAddonsOnly",
		Operator: corev1.TolerationOpExists,
	}

	// TolerateAll returns tolerations to tolerate all taints. When used, it is not necessary
	// to include the user's custom tolerations because we already tolerate everything.
	TolerateAll = []corev1.Toleration{
		TolerateCriticalAddonsOnly,
		{
			Effect:   corev1.TaintEffectNoSchedule,
			Operator: corev1.TolerationOpExists,
		},
		{
			Effect:   corev1.TaintEffectNoExecute,
			Operator: corev1.TolerationOpExists,
		},
	}
)

func DefaultOperatorCASignerName() string {
	return fmt.Sprintf("%s@%d", TigeraOperatorCAIssuerPrefix, time.Now().Unix())
}

// AnnotationHash is to generate a hash that can be included in a Deployment
// or DaemonSet to trigger a restart/rolling update when a ConfigMap or Secret
// is updated.
func AnnotationHash(i interface{}) string {
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%q", i)))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// SecretsAnnotationHash generates a hash based off of the data in each secrets Data field that can be used by
// Deployments or DaemonSets to trigger a restart/rolling update based on changes to one of more secrets data.
func SecretsAnnotationHash(secrets ...*corev1.Secret) string {
	var annoteArr []map[string][]byte
	for _, secret := range secrets {
		annoteArr = append(annoteArr, secret.Data)
	}

	return AnnotationHash(annoteArr)
}

// OperatorNamespace returns the namespace the operator is running in. If the namespace is defined in the environment
// with the OPERATOR_NAMESPACE key then that is return, otherwise the default "tigera-operator" namespace is returned.
func OperatorNamespace() string {
	v, ok := os.LookupEnv("OPERATOR_NAMESPACE")
	if ok {
		return v
	}
	return "tigera-operator"
}
