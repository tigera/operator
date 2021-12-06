package utils_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("", func() {

	var (
		initContainer corev1.Container
		container     corev1.Container
		volumes       []corev1.Volume
		volumeMounts  []corev1.VolumeMount
		podSpec       corev1.Pod
	)
	BeforeEach(func() {
		volumes = []corev1.Volume{}
		volumeMounts = []corev1.VolumeMount{}
		container = corev1.Container{VolumeMounts: volumeMounts}
		initContainer = corev1.Container{VolumeMounts: volumeMounts}
		podSpec = corev1.Pod{
			Spec: corev1.PodSpec{
				Containers:     []corev1.Container{container},
				InitContainers: []corev1.Container{initContainer},
				Volumes:        volumes,
			},
		}
	})

	It("Should create ", func() {
		
	})

	Expect(err).NotTo(HaveOccurred())

})
