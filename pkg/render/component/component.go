package component

import (
	operator "github.com/tigera/operator/api/v1"
	rutil "github.com/tigera/operator/pkg/render/util"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Component interface {
	// ResolveImages should call components.GetReference for all images that the Component
	// needs, passing 'is' to the GetReference call and if there are any errors those
	// are returned. It is valid to pass nil for 'is' as GetReference accepts the value.
	// ResolveImages must be called before Objects is called for the component.
	ResolveImages(is *operator.ImageSet) error

	// Objects returns the lists of objects in this component that should be created and/or deleted during
	// rendering.
	Objects() (objsToCreate, objsToDelete []client.Object)

	// Ready returns true if the component is ready to be created.
	Ready() bool

	// SupportedOSTypes returns operating systems that is supported of the components returned by the Objects() function.
	// The "componentHandler" converts the returned OSTypes to a node selectors for the "kubernetes.io/os" label on client.Objects
	// that create pods. Return OSTypeAny means that no node selector should be set for the "kubernetes.io/os" label.
	SupportedOSType() rutil.OSType
}
