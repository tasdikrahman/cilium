// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/daemon/options"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/viper"
)

const (
	// AllowLocalhostAuto defaults to policy except when running in
	// Kubernetes where it then defaults to "always"
	AllowLocalhostAuto = "auto"

	// AllowLocalhostAlways always allows the local stack to reach local
	// endpoints
	AllowLocalhostAlways = "always"

	// AllowLocalhostPolicy requires a policy rule to allow the local stack
	// to reach particular endpoints or policy enforcement must be
	// disabled.
	AllowLocalhostPolicy = "policy"

	// ModePreFilterNative for loading progs with xdpdrv
	ModePreFilterNative = "native"

	// ModePreFilterGeneric for loading progs with xdpgeneric
	ModePreFilterGeneric = "generic"
)

// CLI flags
const (
	autoIPv6NodeRoutes    = "auto-ipv6-node-routes" // obsoleted (GH-4082)
	autoRouting           = "auto-routing"
	announceAutoRouting   = "announce-auto-routing"
	k8sUseNodeAnnotations = "k8s-use-node-annotations"
)

// Config is the configuration used by Daemon.
type Config struct {
	BpfDir          string     // BPF template files directory
	LibDir          string     // Cilium library files directory
	RunDir          string     // Cilium runtime directory
	NAT46Prefix     *net.IPNet // NAT46 IPv6 Prefix
	Device          string     // Receive device
	DevicePreFilter string     // XDP device
	ModePreFilter   string     // XDP mode, values: { native | generic }
	HostV4Addr      net.IP     // Host v4 address of the snooping device
	HostV6Addr      net.IP     // Host v6 address of the snooping device
	IPv4Disabled    bool       // Disable IPv4 allocation
	LBInterface     string     // Set with name of the interface to loadbalance packets from

	Tunnel string // Tunnel mode

	DryMode       bool // Do not create BPF maps, devices, ..
	RestoreState  bool // RestoreState restores the state from previous running daemons.
	KeepConfig    bool // Keep configuration of existing endpoints when starting up.
	KeepTemplates bool // Do not overwrite the template files

	// AllowLocalhost defines when to allows the local stack to local endpoints
	// values: { auto | always | policy }
	AllowLocalhost string

	// alwaysAllowLocalhost is set based on the value of AllowLocalhost and
	// is either set to true when localhost can always reach local
	// endpoints or false when policy should be evaluated
	alwaysAllowLocalhost bool

	// StateDir is the directory where runtime state of endpoints is stored
	StateDir string

	// Options changeable at runtime
	Opts *option.BoolOptions

	// Mutex for serializing configuration updates to the daemon.
	ConfigPatchMutex lock.RWMutex

	// Monitor contains the configuration for the node monitor.
	Monitor *models.MonitorStatus

	// AccessLog is the path to the access log of supported L7 requests observed.
	AccessLog string

	// AgentLabels contains additional labels to identify this agent in monitor events.
	AgentLabels []string

	routingConfig *node.RoutingConfiguration
}

func (c *Config) deriveNodeRoutingConfiguration() *node.RoutingConfiguration {
	routingConfiguration := node.RoutingConfiguration{}
	switch strings.ToLower(c.Tunnel) {
	case "vxlan":
		routingConfiguration.Encapsulation = node.EncapsulationVXLAN
	case "geneve":
		routingConfiguration.Encapsulation = node.EncapsulationGeneve
	case "disabled", "false":
		routingConfiguration.Encapsulation = node.EncapsulationDisabled
	default:
		log.Fatalf("Unknown encapsulation type '%s'. Supported values are vxlan, geneve, and disabled", c.Tunnel)
	}

	if viper.GetBool(autoRouting) {
		routingConfiguration.DirectRouting.InstallRoutes = true
	}

	if viper.GetBool(announceAutoRouting) {
		routingConfiguration.DirectRouting.Announce = true
	}

	return &routingConfiguration
}

// initialize is called early on in bootstrapping and initializes and validates
// the configuration
func (c *Config) initialize() {
	c.routingConfig = c.deriveNodeRoutingConfiguration()
}

func NewConfig() *Config {
	return &Config{
		Opts:    option.NewBoolOptions(&options.Library),
		Monitor: &models.MonitorStatus{Cpus: int64(runtime.NumCPU()), Npages: 64, Pagesize: int64(os.Getpagesize()), Lost: 0, Unknown: 0},
	}
}

func (c *Config) IsLBEnabled() bool {
	return c.LBInterface != ""
}
