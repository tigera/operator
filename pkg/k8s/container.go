package k8s

import (
	"fmt"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
)

type Container struct {
	ctr corev1.Container

	srvc *corev1.Service

	imageComponent components.Component

	mountedSecrets    []*corev1.Secret
	mountedConfigMaps []*corev1.ConfigMap
}

type VolumeMountOption func(*corev1.VolumeMount)

func NewContainer(name string, imageComponent components.Component) *Container {
	return &Container{
		imageComponent: imageComponent,
		ctr: corev1.Container{
			Name:            name,
			ImagePullPolicy: render.ImagePullPolicy(),
		},
	}
}

func (ctr *Container) ApplyImageSet(installation *operatorv1.InstallationSpec, imageSet *operatorv1.ImageSet) error {
	reg := installation.Registry
	path := installation.ImagePath
	prefix := installation.ImagePrefix

	image, err := components.GetReference(ctr.imageComponent, reg, path, prefix, imageSet)
	if err != nil {
		return err
	}

	ctr.ctr.Image = image
	return nil
}

func (ctr *Container) AddEnv(env ...corev1.EnvVar) *Container {
	ctr.ctr.Env = append(ctr.ctr.Env, env...)
	return ctr
}

func (ctr *Container) MountSecret(path string, scrt *corev1.Secret, opts ...VolumeMountOption) *Container {
	if ctr.SecretMounted(scrt.Name) {
		return ctr
	}

	ctr.mountedSecrets = append(ctr.mountedSecrets, scrt)
	ctr.addVolumeMount(fmt.Sprintf("%s-%s", scrt.Name, "scrt"), path, opts...)
	return ctr
}

func (ctr *Container) SecretMounted(name string) bool {
	for _, scrt := range ctr.mountedSecrets {
		if scrt.Name == name {
			return true
		}
	}
	return false
}

func (ctr *Container) MountConfigMap(path string, cm *corev1.ConfigMap, opts ...VolumeMountOption) *Container {
	if ctr.ConfigMapMounted(cm.Name) {
		return ctr
	}

	ctr.mountedConfigMaps = append(ctr.mountedConfigMaps, cm)
	ctr.addVolumeMount(fmt.Sprintf("%s-%s", cm.Name, "cm"), path, opts...)
	return ctr
}

func (ctr *Container) AddService(srv *corev1.Service) *Container {
	// TODO add target ports, this needs to be deduplicated.
	//for _, port := range srv.Spec.Ports {
	//	ctr.ctr.Ports = append(ctr.ctr.Ports, corev1.ContainerPort{
	//		Name:          port.Name,
	//		ContainerPort: port.Port,
	//	})
	//}

	ctr.srvc = srv
	return ctr
}

func (ctr *Container) ConfigMapMounted(name string) bool {
	for _, cm := range ctr.mountedConfigMaps {
		if cm.Name == name {
			return true
		}
	}
	return false
}

func (ctr *Container) addVolumeMount(name, path string, opts ...VolumeMountOption) {
	mount := corev1.VolumeMount{
		Name:      name,
		MountPath: path,
	}

	for _, opt := range opts {
		opt(&mount)
	}

	ctr.ctr.VolumeMounts = append(ctr.ctr.VolumeMounts, mount)
}

func (ctr *Container) Key() string {
	return ctr.ctr.Name
}
