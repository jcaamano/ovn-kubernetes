/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	userdefinednetworkv1 "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
)

// Layer3ConfigApplyConfiguration represents a declarative configuration of the Layer3Config type for use
// with apply.
type Layer3ConfigApplyConfiguration struct {
	Role        *userdefinednetworkv1.NetworkRole    `json:"role,omitempty"`
	MTU         *int32                               `json:"mtu,omitempty"`
	Subnets     []Layer3SubnetApplyConfiguration     `json:"subnets,omitempty"`
	JoinSubnets *userdefinednetworkv1.DualStackCIDRs `json:"joinSubnets,omitempty"`
}

// Layer3ConfigApplyConfiguration constructs a declarative configuration of the Layer3Config type for use with
// apply.
func Layer3Config() *Layer3ConfigApplyConfiguration {
	return &Layer3ConfigApplyConfiguration{}
}

// WithRole sets the Role field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Role field is set to the value of the last call.
func (b *Layer3ConfigApplyConfiguration) WithRole(value userdefinednetworkv1.NetworkRole) *Layer3ConfigApplyConfiguration {
	b.Role = &value
	return b
}

// WithMTU sets the MTU field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the MTU field is set to the value of the last call.
func (b *Layer3ConfigApplyConfiguration) WithMTU(value int32) *Layer3ConfigApplyConfiguration {
	b.MTU = &value
	return b
}

// WithSubnets adds the given value to the Subnets field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Subnets field.
func (b *Layer3ConfigApplyConfiguration) WithSubnets(values ...*Layer3SubnetApplyConfiguration) *Layer3ConfigApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithSubnets")
		}
		b.Subnets = append(b.Subnets, *values[i])
	}
	return b
}

// WithJoinSubnets sets the JoinSubnets field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the JoinSubnets field is set to the value of the last call.
func (b *Layer3ConfigApplyConfiguration) WithJoinSubnets(value userdefinednetworkv1.DualStackCIDRs) *Layer3ConfigApplyConfiguration {
	b.JoinSubnets = &value
	return b
}
