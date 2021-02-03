package util

import (
	"crypto/sha1"
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// AnnotationHash is to generate a hash that can be included in a Deployment
// or DaemonSet to trigger a restart/rolling update when a ConfigMap or Secret
// is updated.
func AnnotationHash(i interface{}) string {
	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("%q", i)))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// rutil.SecretsAnnotationHash generates a hash based off of the data in each secrets Data field that can be used by Deployments
// or DaemonSets to trigger a restart/rolling update based on changes to one of more secrets data
func SecretsAnnotationHash(secrets ...*corev1.Secret) string {
	var annoteArr []map[string][]byte
	for _, secret := range secrets {
		annoteArr = append(annoteArr, secret.Data)
	}

	return AnnotationHash(annoteArr)
}
