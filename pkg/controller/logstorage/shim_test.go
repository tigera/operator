// This file is here so that we can export a constructor to be used by the tests in the logstorage_test package, but since
// this is an _test file it will only be available for when running tests.
package logstorage

import (
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/status"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewReconcilerWithShims(
	cli client.Client,
	schema *runtime.Scheme,
	status *status.StatusManager,
	provider operatorv1.Provider,
	resolvConfPath string) (*ReconcileLogStorage, error) {

	return newReconciler(cli, schema, status, resolvConfPath, provider)
}
