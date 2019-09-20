package render

const (
	CNICalico = "calico"
	CNINone   = "none"
)

type NetworkConfig struct {
	CNI                  string
	NodenameFileOptional bool
}
