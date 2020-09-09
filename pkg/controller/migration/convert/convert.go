// package convert reads config from existing Calico installations that are not
// managed by Operator, and generates Operator Config that can be used
// to configure a similar cluster.
package convert

import (
	"context"
	"fmt"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/migration/cni"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var log = logf.Log.WithName("migration_convert")

var ctx = context.Background()

type checkedFields struct {
	envVars map[string]bool
}

type components struct {
	node            CheckedDaemonSet
	kubeControllers *appsv1.Deployment
	typha           *appsv1.Deployment

	// client is used to resolve spec fields that reference other data sources
	client client.Client

	cni cni.NetworkComponents
}

// getComponents loads the main calico components into structs for later parsing.
func getComponents(ctx context.Context, client client.Client) (*components, error) {
	var ds = appsv1.DaemonSet{}

	// verify canal isn't present, or block
	if err := client.Get(ctx, types.NamespacedName{
		Name:      "canal-node",
		Namespace: metav1.NamespaceSystem,
	}, &ds); err == nil {
		return nil, fmt.Errorf("detected existing canal installation")
	} else if !errors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to check for existing canal installation: %v", err)
	}

	if err := client.Get(ctx, types.NamespacedName{
		Name:      "calico-node",
		Namespace: metav1.NamespaceSystem,
	}, &ds); err != nil {
		return nil, err
	}

	var kc = new(appsv1.Deployment)
	if err := client.Get(ctx, types.NamespacedName{
		Name:      "calico-kube-controllers",
		Namespace: metav1.NamespaceSystem,
	}, kc); err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get kube-controllers deployment: %v", err)
		}
		log.Info("did not detect kube-controllers")
		kc = nil
	}

	var t = new(appsv1.Deployment)
	if err := client.Get(ctx, types.NamespacedName{
		Name:      "calico-typha",
		Namespace: metav1.NamespaceSystem,
	}, t); err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get typha deployment: %v", err)
		}
		// typha is optional, so just log.
		log.Info("did not detect typha")
		t = nil
	}

	comps := &components{
		client: client,
		node: CheckedDaemonSet{
			ds,
			map[string]checkedFields{},
		},
		kubeControllers: kc,
		typha:           t,
	}

	// do some upfront processing of CNI by loading it into comps
	var err error
	comps.cni, err = loadCNI(comps)

	return comps, err
}

// loadCNI pulls the CNI network config from it's env var source within components
// and then returns the parsed data.
func loadCNI(comps *components) (nc cni.NetworkComponents, err error) {
	// do some upfront processing of CNI by loading it into comps
	c := getContainer(comps.node.Spec.Template.Spec, containerInstallCNI)
	if c == nil {
		return
	}

	cniConfig, err := comps.node.getEnv(ctx, comps.client, containerInstallCNI, "CNI_NETWORK_CONFIG")
	if err != nil {
		return nc, err
	}
	if cniConfig != nil {
		nc, err = cni.Parse(*cniConfig)
	}

	return nc, err
}

// GetExistingInstallation creates an Installation resource from an existing Calico install (i.e.
// one that is not managed by operator). If the existing installation cannot be represented by an Installation
// resource, an ErrIncompatibleCluster is returned.
func Convert(ctx context.Context, client client.Client, install *operatorv1.Installation) error {
	comps, err := getComponents(ctx, client)
	if err != nil {
		if kerrors.IsNotFound(err) {
			log.Error(err, "no existing install found: %v", err)
			return nil
		}
		return err
	}

	for _, hdlr := range handlers {
		if err := hdlr(comps, install); err != nil {
			return err
		}
	}

	// Handle the remaining FelixVars last because we only want to take env vars which weren't accounted
	// for by the other handlers
	if err := handleFelixVars(comps); err != nil {
		return err
	}

	// check for unchecked env vars
	if uncheckedVars := comps.node.uncheckedVars(); len(uncheckedVars) != 0 {
		return ErrIncompatibleCluster{fmt.Sprintf("unexpected env var: %s", uncheckedVars)}
	}

	return nil
}
