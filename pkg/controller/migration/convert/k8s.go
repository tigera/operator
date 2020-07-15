package convert

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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
	return getEnv(ctx, client, c.Env, key)
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

// getEnv gets an environment variable from a container. Nil is returned
// if the requested Key was not found.
func getEnv(ctx context.Context, client client.Client, env []corev1.EnvVar, key string) (*string, error) {
	for _, e := range env {
		if e.Name == key {
			val, err := getEnvVar(ctx, client, e)
			return &val, err
		}
	}
	return nil, nil
}

func getEnvVar(ctx context.Context, client client.Client, e corev1.EnvVar) (string, error) {
	if e.Value != "" {
		return e.Value, nil
	}
	// if Value is empty, one of the ConfigMapKeyRefs must be used
	if e.ValueFrom.ConfigMapKeyRef != nil {
		cm := v1.ConfigMap{}
		err := client.Get(ctx, types.NamespacedName{
			Name:      e.ValueFrom.ConfigMapKeyRef.LocalObjectReference.Name,
			Namespace: "kube-system",
		}, &cm)
		if err != nil {
			return "", err
		}
		v := cm.Data[e.ValueFrom.ConfigMapKeyRef.Key]
		return v, nil
	}

	// TODO: if we just need to check that a variable _is_ a secretRef, fieldRef, and resourceFieldRef,
	// we'll need to add a different method.
	return "", ErrIncompatibleCluster{"only configMapRef & explicit values supported for env vars at this time"}
}
