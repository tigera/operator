// +build !ignore_autogenerated

// Code generated by operator-sdk-v0.18.2. DO NOT EDIT.

package v1beta1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AmazonCloudIntegration) DeepCopyInto(out *AmazonCloudIntegration) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	out.Status = in.Status
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AmazonCloudIntegration.
func (in *AmazonCloudIntegration) DeepCopy() *AmazonCloudIntegration {
	if in == nil {
		return nil
	}
	out := new(AmazonCloudIntegration)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AmazonCloudIntegration) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AmazonCloudIntegrationList) DeepCopyInto(out *AmazonCloudIntegrationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AmazonCloudIntegration, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AmazonCloudIntegrationList.
func (in *AmazonCloudIntegrationList) DeepCopy() *AmazonCloudIntegrationList {
	if in == nil {
		return nil
	}
	out := new(AmazonCloudIntegrationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AmazonCloudIntegrationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AmazonCloudIntegrationSpec) DeepCopyInto(out *AmazonCloudIntegrationSpec) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AmazonCloudIntegrationSpec.
func (in *AmazonCloudIntegrationSpec) DeepCopy() *AmazonCloudIntegrationSpec {
	if in == nil {
		return nil
	}
	out := new(AmazonCloudIntegrationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AmazonCloudIntegrationStatus) DeepCopyInto(out *AmazonCloudIntegrationStatus) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AmazonCloudIntegrationStatus.
func (in *AmazonCloudIntegrationStatus) DeepCopy() *AmazonCloudIntegrationStatus {
	if in == nil {
		return nil
	}
	out := new(AmazonCloudIntegrationStatus)
	in.DeepCopyInto(out)
	return out
}
