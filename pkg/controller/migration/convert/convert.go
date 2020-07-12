// package convert reads config from existing Calico installations that are not
// managed by Operator, and generates Operator Config that can be used
// to configure a similar cluster.
package convert

import (
	"context"
	"fmt"
	"log"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"

	"github.com/containernetworking/cni/libcni"
	calicocni "github.com/projectcalico/cni-plugin/pkg/types"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var ctx = context.Background()

// Installation represents the configuration pulled from the existing install.
type Installation struct {
	operatorv1.Installation

	// The following fields are not yet exposed in the
	// operator API, and serve as a temporary store during prototyping.
	// The goal is to eventually remove them all and remove this type,
	// using operatorv1.Installation directly.
	FelixEnvVars []corev1.EnvVar
	CNIConfig    string
}

type checkedFields struct {
	envVars map[string]bool
}

type components struct {
	node            CheckedDaemonSet
	kubeControllers appsv1.Deployment
	typha           appsv1.Deployment

	// Calico CNI conf
	// TODO: is cni-private netconf different? is it ok to only use the OS one?
	// TODO: where do cni config 'routes' & 'ranges' come into play between these datastructures?
	calicoCNIConfig *calicocni.NetConf

	// other CNI plugins in the conflist.
	pluginCNIConfig map[string]*libcni.NetworkConfig

	// client is used to resolve spec fields that reference other data sources
	client client.Client
}

// getComponents loads the main calico components into structs for later parsing.
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

	var t = appsv1.Deployment{}
	if err := client.Get(ctx, types.NamespacedName{
		Name:      "calico-typha",
		Namespace: metav1.NamespaceSystem,
	}, &t); err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		} else {
			// typha is optional, so just log.
			log.Print("did not detect typha")
		}
	}

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

type Converter struct {
	Client client.Client
}

// GetExistingInstallation creates an Installation resource from an existing Calico install (i.e.
// one that is not managed by operator). If the existing installation cannot be represented by an Installation
// resource, an ErrIncompatibleCluster is returned.
func (p Converter) Convert() (*operatorv1.Installation, error) {
	config := &Installation{}

	comps, err := getComponents(ctx, p.Client)
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

	// check for unchecked env vars
	if uncheckedVars := comps.node.uncheckedVars(); len(uncheckedVars) != 0 {
		return nil, ErrIncompatibleCluster{fmt.Sprintf("unexpected env var: %s", uncheckedVars)}
	}

	return &config.Installation, nil
}
