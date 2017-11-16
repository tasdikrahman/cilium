// +build !ignore_autogenerated

// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file was autogenerated by deepcopy-gen. Do not edit it manually!

package v1

import (
	api "github.com/cilium/cilium/pkg/policy/api"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
	reflect "reflect"
)

func init() {
	SchemeBuilder.Register(RegisterDeepCopies)
}

// RegisterDeepCopies adds deep-copy functions to the given scheme. Public
// to allow building arbitrary schemes.
//
// Deprecated: deepcopy registration will go away when static deepcopy is fully implemented.
func RegisterDeepCopies(scheme *runtime.Scheme) error {
	return scheme.AddGeneratedDeepCopyFuncs(
		conversion.GeneratedDeepCopyFunc{Fn: func(in interface{}, out interface{}, c *conversion.Cloner) error {
			in.(*CiliumNetworkPolicy).DeepCopyInto(out.(*CiliumNetworkPolicy))
			return nil
		}, InType: reflect.TypeOf(&CiliumNetworkPolicy{})},
		conversion.GeneratedDeepCopyFunc{Fn: func(in interface{}, out interface{}, c *conversion.Cloner) error {
			in.(*CiliumNetworkPolicyList).DeepCopyInto(out.(*CiliumNetworkPolicyList))
			return nil
		}, InType: reflect.TypeOf(&CiliumNetworkPolicyList{})},
		conversion.GeneratedDeepCopyFunc{Fn: func(in interface{}, out interface{}, c *conversion.Cloner) error {
			in.(*CiliumNetworkPolicyNodeStatus).DeepCopyInto(out.(*CiliumNetworkPolicyNodeStatus))
			return nil
		}, InType: reflect.TypeOf(&CiliumNetworkPolicyNodeStatus{})},
		conversion.GeneratedDeepCopyFunc{Fn: func(in interface{}, out interface{}, c *conversion.Cloner) error {
			in.(*CiliumNetworkPolicyStatus).DeepCopyInto(out.(*CiliumNetworkPolicyStatus))
			return nil
		}, InType: reflect.TypeOf(&CiliumNetworkPolicyStatus{})},
		conversion.GeneratedDeepCopyFunc{Fn: func(in interface{}, out interface{}, c *conversion.Cloner) error {
			in.(*Timestamp).DeepCopyInto(out.(*Timestamp))
			return nil
		}, InType: reflect.TypeOf(&Timestamp{})},
	)
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumNetworkPolicy) DeepCopyInto(out *CiliumNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.Spec != nil {
		in, out := &in.Spec, &out.Spec
		if *in == nil {
			*out = nil
		} else {
			*out = new(api.Rule)
			(*in).DeepCopyInto(*out)
		}
	}
	if in.Specs != nil {
		in, out := &in.Specs, &out.Specs
		*out = make(api.Rules, len(*in))
		for i := range *in {
			if (*in)[i] == nil {
				(*out)[i] = nil
			} else {
				(*out)[i] = new(api.Rule)
				(*in)[i].DeepCopyInto((*out)[i])
			}
		}
	}
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumNetworkPolicy.
func (in *CiliumNetworkPolicy) DeepCopy() *CiliumNetworkPolicy {
	if in == nil {
		return nil
	}
	out := new(CiliumNetworkPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumNetworkPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	} else {
		return nil
	}
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumNetworkPolicyList) DeepCopyInto(out *CiliumNetworkPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]CiliumNetworkPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumNetworkPolicyList.
func (in *CiliumNetworkPolicyList) DeepCopy() *CiliumNetworkPolicyList {
	if in == nil {
		return nil
	}
	out := new(CiliumNetworkPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *CiliumNetworkPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	} else {
		return nil
	}
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumNetworkPolicyNodeStatus) DeepCopyInto(out *CiliumNetworkPolicyNodeStatus) {
	*out = *in
	in.LastUpdated.DeepCopyInto(&out.LastUpdated)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumNetworkPolicyNodeStatus.
func (in *CiliumNetworkPolicyNodeStatus) DeepCopy() *CiliumNetworkPolicyNodeStatus {
	if in == nil {
		return nil
	}
	out := new(CiliumNetworkPolicyNodeStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CiliumNetworkPolicyStatus) DeepCopyInto(out *CiliumNetworkPolicyStatus) {
	*out = *in
	if in.Nodes != nil {
		in, out := &in.Nodes, &out.Nodes
		*out = make(map[string]CiliumNetworkPolicyNodeStatus, len(*in))
		for key, val := range *in {
			newVal := new(CiliumNetworkPolicyNodeStatus)
			val.DeepCopyInto(newVal)
			(*out)[key] = *newVal
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CiliumNetworkPolicyStatus.
func (in *CiliumNetworkPolicyStatus) DeepCopy() *CiliumNetworkPolicyStatus {
	if in == nil {
		return nil
	}
	out := new(CiliumNetworkPolicyStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Timestamp.
func (in *Timestamp) DeepCopy() *Timestamp {
	if in == nil {
		return nil
	}
	out := new(Timestamp)
	in.DeepCopyInto(out)
	return out
}