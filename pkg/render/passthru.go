package render

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func NewDeletionPassthrough(objs ...client.Object) Component {
	return &passthroughComponent{isDelete: true, objs: objs}
}

func NewPassthrough(objs ...client.Object) Component {
	return &passthroughComponent{isDelete: false, objs: objs}
}

// passthroughComponent is an implementation of a Component that simply passes back
// the objects it was given unmodified.
type passthroughComponent struct {
	isDelete bool
	objs     []client.Object
}

// ResolveImages should call components.GetReference for all images that the Component
// needs, passing 'is' to the GetReference call and if there are any errors those
// are returned. It is valid to pass nil for 'is' as GetReference accepts the value.
// ResolveImages must be called before Objects is called for the component.
func (p *passthroughComponent) ResolveImages(is *operatorv1.ImageSet) error {
	return nil
}

// Objects returns the lists of objects in this component that should be created and/or deleted during
// rendering.
func (p *passthroughComponent) Objects() (objsToCreate []client.Object, objsToDelete []client.Object) {
	// Filter out nil objects. This makes it easier for the calling code, so we don't need to duplicate
	// this filtering logic in all the controllers that user this component.
	objs := []client.Object{}
	for _, o := range p.objs {
		if o == nil {
			continue
		}
		objs = append(objs, o)
	}
	if p.isDelete {
		return nil, objs
	}
	return objs, nil
}

// Ready returns true if the component is ready to be created.
func (p *passthroughComponent) Ready() bool {
	return true
}

// SupportedOSTypes returns operating systems that is supported of the components returned by the Objects() function.
// The "componentHandler" converts the returned OSTypes to a node selectors for the "kubernetes.io/os" label on client.Objects
// that create pods. Return OSTypeAny means that no node selector should be set for the "kubernetes.io/os" label.
func (p *passthroughComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeAny
}
