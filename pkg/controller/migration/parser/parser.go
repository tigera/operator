// Package parser reads config from existing Calico installations that are not
// managed by Operator, and generates Operator Config that can be used
// to configure a similar cluster.
package parser

import (
	"context"
	"fmt"
	"log"

	"github.com/containernetworking/cni/libcni"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"

	calicocni "github.com/projectcalico/cni-plugin/pkg/types"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ctx = context.Background()

// Config represents the configuration pulled from the existing install.
type Config struct {
	operatorv1.Installation

	// The following fields are not yet exposed in the
	// operator API, and serve as a temporary store during prototyping.
	// The goal is to eventually remove them all and remove this type,
	// using operatorv1.Installation directly.
	FelixEnvVars []corev1.EnvVar
	CNIConfig    string
}

// ErrIncompatibleCluster is thrown if a config option was detected in the existing install
// which Operator does not currently expose.
type ErrIncompatibleCluster struct {
	err string
}

func (e ErrIncompatibleCluster) Error() string {
	return e.err
}

type checkedFields struct {
	envVars map[string]bool
}

type components struct {
	node            CheckedDaemonSet
	kubeControllers appsv1.Deployment
	typha           appsv1.Deployment

	// other CNI plugin conf
	pluginCNIConfig map[string]*libcni.NetworkConfig
	// calico CNI conf
	// TODO: is cni-private netconf different? is it ok to only use the OS one?
	// TODO: where do cni config 'routes' & 'ranges' come into play between these datastructures?
	calicoCNIConfig *calicocni.NetConf

	client client.Client
}

func getComponents(ctx context.Context, client client.Client) (*components, error) {
	var ds = appsv1.DaemonSet{}
	if err := client.Get(ctx, types.NamespacedName{
		Name:      "calico-node",
		Namespace: metav1.NamespaceSystem,
	}, &ds); err != nil {
		return nil, err
	}

	var kc = appsv1.Deployment{}
	if err := client.Get(ctx, types.NamespacedName{
		Name:      "calico-kube-controllers",
		Namespace: metav1.NamespaceSystem,
	}, &kc); err != nil {
		return nil, err
	}

	// TODO: handle partial detection
	// var t = appsv1.Deployment{}
	// if err := client.Get(ctx, types.NamespacedName{
	// 	Name:      "calico-typha",
	// 	Namespace: metav1.NamespaceSystem,
	// }, &t); err != nil {
	// 	return nil, err
	// }

	comps := &components{
		client: client,
		node: CheckedDaemonSet{
			ds,
			map[string]checkedFields{},
		},
		kubeControllers: kc,
		// typha:           t,

	}

	err := loadCNI(comps)

	return comps, err
}

// GetExistingInstallation creates an Installation resource from an existing Calico install (i.e.
// one that is not managed by operator). If the existing installation cannot be represented by an Installation
// resource, an ErrIncompatibleCluster is returned.
func GetExistingInstallation(ctx context.Context, client client.Client) (*Config, error) {
	config := &Config{}

	comps, err := getComponents(ctx, client)
	if err != nil {
		if kerrors.IsNotFound(err) {
			log.Print("no existing install found: ", err)
			return nil, nil
		}
		return nil, err
	}

	if err := handleNetwork(comps, config); err != nil {
		return nil, err
	}

	if err := handleCore(comps, config); err != nil {
		return nil, err
	}

	uncheckedVars := comps.node.uncheckedVars()
	// go back through the list at the end to make sure we checked everything.
	if len(uncheckedVars) != 0 {
		return nil, ErrIncompatibleCluster{fmt.Sprintf("unexpected env var: %s", uncheckedVars)}
	}

	return config, nil
}

func getContainer(containers []corev1.Container, name string) *corev1.Container {
	for _, container := range containers {
		if container.Name == name {
			return &container
		}
	}
	return nil
}

func getContainers(spec corev1.PodSpec, name string) *corev1.Container {
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
