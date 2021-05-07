package authentication

import corev1 "k8s.io/api/core/v1"

type KeyValidatorConfig interface {
	Issuer() string
	ClientID() string
	// RequiredConfigMaps returns config maps that the KeyValidatorConfig implementation requires.
	RequiredConfigMaps(namespace string) []*corev1.ConfigMap
	// RequiredEnv returns env variables that the KeyValidatorConfig implementation requires.
	RequiredEnv(prefix string) []corev1.EnvVar
	// RequiredAnnotations returns annotations that the KeyValidatorConfig implementation requires.
	RequiredAnnotations() map[string]string
	// RequiredSecrets returns secrets that the KeyValidatorConfig implementation requires.
	RequiredSecrets(namespace string) []*corev1.Secret
	// RequiredVolumeMounts returns volume mounts that the KeyValidatorConfig implementation requires.
	RequiredVolumeMounts() []corev1.VolumeMount
	// RequiredVolumes returns volumes that the KeyValidatorConfig implementation requires.
	RequiredVolumes() []corev1.Volume
}
