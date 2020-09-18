// package convert reads config from existing Calico installations that are not
// managed by Operator, and generates Operator Config that can be used
// to configure a similar cluster.
package convert

import (
	"context"
	"fmt"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

var log = logf.Log.WithName("migration_convert")

var ctx = context.Background()

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
		return ErrIncompatibleCluster{
			err:       fmt.Sprintf("unexpected env vars: %s", uncheckedVars),
			component: ComponentCalicoNode,
			fix:       "remove these environment variables from the calico-node daemonest",
		}
	}

	return nil
}
