package convert

import corev1 "k8s.io/api/core/v1"

func getContainer(spec corev1.PodSpec, name string) *corev1.Container {
	for _, container := range spec.Containers {
		if container.Name == name {
			return &container
		}
	}
	for _, container := range spec.InitContainers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

func getVolume(spec corev1.PodSpec, name string) *corev1.Volume {
	for _, volume := range spec.Volumes {
		if volume.Name == name {
			return &volume
		}
	}
	return nil
}
