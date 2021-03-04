package convert

import (
	operatorv1 "github.com/tigera/operator/api/v1"
)

func checkTypha(c *components, _ *operatorv1.Installation) error {
	// No validation required.
	return nil
}
