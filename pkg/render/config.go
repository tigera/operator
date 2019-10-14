package render

import (
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
)

const (
	CNICalico = "calico"
	CNINone   = "none"
)

type NetworkConfig struct {
	CNI                  string
	NodenameFileOptional bool
	IPPools              []operatorv1.IPPool
}
