package convert

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CheckedDaemonSet keeps track of which fields have been 'checked' by handlers.
// This is done so that at the end of the migration, any 'unchecked' fields can be reported
// and errored.
type CheckedDaemonSet struct {
	appsv1.DaemonSet

	checkedVars map[string]checkedFields
}

// uncheckedVars returns a list of all environment variables which
// were not checked by handlers.
func (r *CheckedDaemonSet) uncheckedVars() []string {
	unchecked := []string{}

	for _, t := range r.Spec.Template.Spec.Containers {
		for _, v := range t.Env {
			if _, ok := r.checkedVars[t.Name].envVars[v.Name]; !ok {
				unchecked = append(unchecked, t.Name+"/"+v.Name)
			}
		}
	}

	for _, t := range r.Spec.Template.Spec.InitContainers {
		for _, v := range t.Env {
			if _, ok := r.checkedVars[t.Name].envVars[v.Name]; !ok {
				unchecked = append(unchecked, t.Name+"/"+v.Name)
			}
		}
	}

	return unchecked
}

// getEnv gets the value of an environment variable and marks that it has been checked.
func (r *CheckedDaemonSet) getEnv(ctx context.Context, client client.Client, container string, key string) (*string, error) {
	c := getContainer(r.Spec.Template.Spec, container)
	if c == nil {
		return nil, ErrIncompatibleCluster{fmt.Sprintf("couldn't find %s container in existing daemonset", container)}
	}
	r.ignoreEnv(container, key)

	for _, e := range c.Env {
		if e.Name == key {
			if e.ValueFrom == nil {
				return &e.Value, nil
			}
			if e.ValueFrom.ConfigMapKeyRef != nil {
				cm := v1.ConfigMap{}
				err := client.Get(ctx, types.NamespacedName{
					Name:      e.ValueFrom.ConfigMapKeyRef.LocalObjectReference.Name,
					Namespace: "kube-system",
				}, &cm)
				if err != nil {
					return nil, err
				}
				v := cm.Data[e.ValueFrom.ConfigMapKeyRef.Key]
				return &v, nil
			}

			return nil, ErrIncompatibleCluster{"only configMapRef & explicit values supported for env vars at this time"}
		}
	}
	return nil, nil
}

// ignoreEnv marks an environment variable as checked so that the migrator
// will not raise an error for it.
func (r *CheckedDaemonSet) ignoreEnv(container, key string) {
	if _, ok := r.checkedVars[container]; !ok {
		r.checkedVars[container] = checkedFields{
			map[string]bool{},
		}
	}
	r.checkedVars[container].envVars[key] = true
}
