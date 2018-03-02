// Copyright 2016-2018 Authors of Cilium
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

package node

import (
	"fmt"
)

// EncapsulationType is a networking encapsulation type
//
// WARNING - STABLE API: This structured is exported to JSON and stored in the
// kvstore. All changes must be done while guaranteeing backwards
// compatibility.
type EncapsulationType string

const (
	// EncapsulationDisabled indicates to disable encapsulation
	EncapsulationDisabled EncapsulationType = "disabled"

	// EncapsulationVXLAN indicates to use VXLAN encapsulation mode
	EncapsulationVXLAN = "vxlan"

	// EncapsulationGeneve indicates to use Geneve encapsulation mode
	EncapsulationGeneve = "geneve"
)

// DirectRoutingConfiguration is the direct routing configuration of a node
//
// WARNING - STABLE API: This structured is exported to JSON and stored in the
// kvstore. All changes must be done while guaranteeing backwards
// compatibility.
type DirectRoutingConfiguration struct {
	// Available indicates that the node's endpoints can be reached via a
	// direct route that uses the node's external IP address as gateway.
	// Enabling this flag does not automatically prefer direct routing,
	// encapsulation must be disabled in order for direct routing to take
	// place.
	Announce bool

	// InstallRoutes indicates that this node automatically installs direct
	// routes to other nodes for their respective endpoint CIDRs.
	InstallRoutes bool
}

// RoutingConfiguration is the configuration of the node that defines how to
// reach endpoints running on the node
//
// WARNING - STABLE API: This structured is exported to JSON and stored in the
// kvstore. All changes must be done while guaranteeing backwards
// compatibility.
type RoutingConfiguration struct {
	// Encapsulation defines whether and how the endpoints on the node can
	// be reached using network encapsulation. Encapsulation is always the
	// preferred routing mode unless it is explicitly disabled.
	Encapsulation EncapsulationType

	// DirectRouting is the direct configuration announced and used
	DirectRouting DirectRoutingConfiguration
}

func (rc RoutingConfiguration) String() string {
	return fmt.Sprintf("encapsulation=%s announce-direct-routing=%t install-direct-routes=%t",
		rc.Encapsulation, rc.DirectRouting.Announce, rc.DirectRouting.InstallRoutes)
}
