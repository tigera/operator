package controller

import (
	"github.com/tigera/operator/pkg/controller/core"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, core.Add)
}
