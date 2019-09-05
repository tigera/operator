package render

type NetworkConfig struct {
	CNI string
}

type Platform string

var (
	PlatformOpenshift Platform = "openshift"
	PlatformEKS       Platform = "eks"
)
