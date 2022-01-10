// Copyright 2017 CNI authors
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

// This is a sample chained plugin that supports multiple CNI versions. It
// parses prevResult according to the cniVersion
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/plugins/pkg/ipam"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

// PluginConf is whatever you expect your configuration json to be. This is whatever
// is passed in on stdin. Your plugin may wish to expose its functionality via
// runtime args, see CONVENTIONS.md in the CNI spec.
type PluginConf struct {
	// This embeds the standard NetConf structure which allows your plugin
	// to more easily parse standard fields like Name, Type, CNIVersion,
	// and PrevResult.
	types.NetConf
	VNI     int    // 10
	VtepDev string // eth0
	DstPort int
	Local   net.IP
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*PluginConf, error) {
	conf := PluginConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	return &conf, nil
}

// cmdAdd is called for ADD requests
func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	// START originating plugin code
	if conf.PrevResult != nil {
		return fmt.Errorf("must be called as the first plugin")
	}

	// Generate some fake container IPs and add to the result
	result := &current.Result{CNIVersion: current.ImplementedSpecVersion}
	// result.Interfaces = []*current.Interface{
	// 	{
	// 		Name:    "intf0",
	// 		Sandbox: args.Netns,
	// 		Mac:     "00:11:22:33:44:55",
	// 	},
	// }
	// result.IPs = []*current.IPConfig{
	// 	{
	// 		Address:   "1.2.3.4/24",
	// 		Gateway:   "1.2.3.1",
	// 		// Interface is an index into the Interfaces array
	// 		// of the Interface element this IP applies to
	// 		Interface: current.Int(0),
	// 	}
	// }
	// END originating plugin code

	// Implement your plugin here

	link, err := setupVxlan(conf.Name, conf.VNI, conf.Local, conf.VtepDev, conf.DstPort)

	if err != nil {
		return err
	}

	ipresult, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}

	// release IP in case of failure
	defer func() {
		ipam.ExecDel(conf.IPAM.Type, args.StdinData)
	}()

	// Convert whatever the IPAM result was into the current Result type
	ipamResult, err := current.NewResultFromResult(ipresult)
	if err != nil {
		return err
	}

	for _, v := range ipamResult.IPs {
		addr := &netlink.Addr{IPNet: &v.Address, Label: ""}
		err = netlink.AddrAdd(link, addr)

		if err != nil {
			return err
		}
	}

	result.Interfaces = append(result.Interfaces, &current.Interface{
		Name: link.Name,
		Mac:  link.HardwareAddr.String(),
	})

	result.IPs = ipamResult.IPs
	result.Routes = ipamResult.Routes

	// Pass through the result for the next plugin
	return types.PrintResult(result, conf.CNIVersion)
}

// cmdDel is called for DELETE requests
func cmdDel(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	link, err := netlink.LinkByName(conf.Name)

	if err != nil {
		_ = netlink.LinkDel(link)
	}

	return err
}

func main() {
	// replace TODO with your plugin name
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("vxlan"))
}

func cmdCheck(args *skel.CmdArgs) error {
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		return err
	}

	_, err = netlink.LinkByName(conf.Name)
	if err != nil {
		return fmt.Errorf("could not locate %q: %v", conf.Name, err)
	}

	return nil
}

func setupVxlan(name string, vni int, local net.IP, parent string, dstport int) (*netlink.Vxlan, error) {
	vxlan := netlink.Vxlan{}
	vxlan.VxlanId = vni
	vxlan.SrcAddr = local
	vxlan.Port = dstport
	vxlan.Name = name

	link, err := netlink.LinkByName(parent)
	if err != nil {
		return nil, err
	}

	vxlan.VtepDevIndex = link.Attrs().Index

	err = netlink.LinkAdd(&vxlan)

	if err != nil {
		return nil, err
	}

	return &vxlan, nil
}
