package k8s

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/tigera/operator/pkg/render/common/secret"

	operatorv1 "github.com/tigera/operator/api/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

type Deployment struct {
	dep appsv1.Deployment

	// Not using a map because order can change and there's not so many containers that it would cause a performance issue.
	ctrs []*Container
}

func NewDeployment(dep appsv1.Deployment) *Deployment {
	return &Deployment{dep: dep}
}

func (d *Deployment) Deployment() *appsv1.Deployment {
	return &d.dep
}

func (d *Deployment) SetPullSecrets(pullSecrets []*corev1.Secret) {
	d.dep.Spec.Template.Spec.ImagePullSecrets = secret.GetReferenceList(pullSecrets)
}

func (d *Deployment) Services() []*corev1.Service {
	var srvs []*corev1.Service
	for _, ctr := range d.ctrs {
		if ctr.srvc != nil {
			ctr.srvc.SetNamespace(d.dep.ObjectMeta.Namespace)
			srvs = append(srvs, ctr.srvc)
		}
	}
	return srvs
}

func (d *Deployment) ApplyImageSet(installation *operatorv1.InstallationSpec, imageSet *operatorv1.ImageSet) error {
	for _, ctr := range d.ctrs {
		if err := ctr.ApplyImageSet(installation, imageSet); err != nil {
			return err
		}
	}
	return nil
}

func (d *Deployment) MountedSecrets() []*corev1.Secret {
	var scrts []*corev1.Secret
	for _, ctr := range d.ctrs {
		for _, scrt := range ctr.mountedSecrets {
			scrt.SetNamespace(d.dep.ObjectMeta.Namespace)
			scrts = append(scrts, scrt)
		}
	}

	return scrts
}

func (d *Deployment) MountedConfigMaps() []*corev1.ConfigMap {
	var cms []*corev1.ConfigMap
	for _, ctr := range d.ctrs {
		for _, cm := range ctr.mountedConfigMaps {
			cm.SetNamespace(d.dep.ObjectMeta.Namespace)
			cms = append(cms, cm)
		}
	}

	return cms
}

func (d *Deployment) Key() string {
	key := d.dep.ObjectMeta.Name
	if d.dep.ObjectMeta.Namespace != "" {
		key += "/" + d.dep.ObjectMeta.Namespace
	}
	return key
}

func (d *Deployment) ReplaceContainers(ctrs ...*Container) {
	for i, ctr := range ctrs {
		if d.HasContainer(ctr.ctr.Name) {
			d.ctrs[i] = ctr
		} else {
			d.ctrs = append(d.ctrs, ctr)
		}
	}
}

func (d *Deployment) AddContainers(ctrs ...*Container) {
	for i, ctr := range ctrs {
		if d.HasContainer(ctr.ctr.Name) {
			d.ctrs[i] = ctr
		} else {
			d.ctrs = append(d.ctrs, ctr)
		}
	}
}

func (d *Deployment) setAnnotations() {
	annots := map[string]string{}
	for _, ctr := range d.ctrs {
		for _, scrt := range ctr.mountedSecrets {
			addAnnotation(annots, fmt.Sprintf("%s-%s", scrt.Name, "scrt"), scrt.Data)
		}

		for _, cm := range ctr.mountedConfigMaps {
			addAnnotation(annots, fmt.Sprintf("%s-%s", cm.Name, "cm"), cm.Data)
		}
	}
	d.dep.Spec.Template.ObjectMeta.Annotations = annots
}

func (d *Deployment) setVolumes() {
	var volumes []corev1.Volume
	for _, ctr := range d.ctrs {
		for _, scrt := range ctr.mountedSecrets {
			name := scrt.Name + "-scrt"
			if d.HasVolume(volumes, name) {
				continue
			}

			volumes = append(volumes, corev1.Volume{
				Name:         scrt.Name + "-scrt",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: scrt.Name}},
			})
		}

		for _, cm := range ctr.mountedConfigMaps {
			name := cm.Name + "-cm"
			if d.HasVolume(volumes, name) {
				continue
			}
			volumes = append(volumes, corev1.Volume{
				Name:         cm.Name + "-cm",
				VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: cm.Name}}},
			})
		}
	}

	d.dep.Spec.Template.Spec.Volumes = volumes
}

func (d *Deployment) HasVolume(volumes []corev1.Volume, name string) bool {
	for _, vol := range volumes {
		if vol.Name == name {
			return true
		}
	}

	return false
}

func (d *Deployment) HasContainer(name string) bool {
	for _, ctr := range d.ctrs {
		if ctr.ctr.Name == name {
			return true
		}
	}
	return false
}

func (d *Deployment) Objects() []client.Object {
	d.setAnnotations()
	d.setVolumes()

	if d.dep.Spec.Template.ObjectMeta.Labels == nil {
		d.dep.Spec.Template.ObjectMeta.Labels = map[string]string{}
	}
	d.dep.Spec.Template.ObjectMeta.Labels["k8s-app"] = d.dep.ObjectMeta.Name

	// Set the service selector.
	for _, svc := range d.Services() {
		if svc.Spec.Selector == nil {
			svc.Spec.Selector = map[string]string{}
		}
		svc.Spec.Selector["k8s-app"] = d.dep.ObjectMeta.Name
	}

	var objs []client.Object
	var ctrs []corev1.Container
	for _, ctr := range d.ctrs {
		ctrs = append(ctrs, ctr.ctr)
	}
	d.dep.Spec.Template.Spec.Containers = ctrs

	objs = append(objs, toClientObjects(d.MountedConfigMaps()...)...)
	objs = append(objs, toClientObjects(d.MountedSecrets()...)...)
	objs = append(objs, &d.dep)
	objs = append(objs, toClientObjects(d.Services()...)...)

	return objs
}

func toClientObjects[E client.Object](objs ...E) []client.Object {
	var clientObjs []client.Object
	for _, obj := range objs {
		clientObjs = append(clientObjs, obj)
	}
	return clientObjs
}
