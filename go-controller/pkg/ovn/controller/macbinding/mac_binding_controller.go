// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

// Package macbinding implements the MAC Binding mirror controller for OKEP-6691
// (Scalable ARP and NDP Broadcast Handling for UDN).
//
// Networks that share a physical uplink form a group. Within each group a
// single "designated" network resolves ARP/ND on the wire; OVN records the
// result in its Gateway Router's SB MAC_Binding rows. This controller mirrors
// those rows onto the SB MAC_Binding of every other ("target") Gateway Router
// in the group, so the targets never need to broadcast ARP/ND themselves.
//
//   - The default group (networks on the shared breth0, i.e. Uplink()=="")
//     always designates the CDN Gateway Router; its targets are the primary
//     L2/L3 UDNs and CUDNs present on the node.
//   - A dedicated uplink group (Uplink()!="") contains only CUDNs; the oldest
//     by CreationTimestamp is the designated, the rest are targets.
//
// Reconciliation is NAD-key driven. A NAD event resolves the network's NetInfo
// with GetNetInfoForNADKey: when the uplink is empty the network is a default
// member and its GR port is added to (or removed from) the default target set;
// when it has an uplink that whole group is recomputed via DoWithLock filtered
// by the uplink plus the CUDNs referencing it. When the NAD is gone its NetInfo
// no longer resolves, so a GC sweep re-checks every tracked network and
// recomputes the groups whose members disappeared.
//
// The controller keeps: designated GR external port -> target GR external
// ports; network -> the designated GR port of its group (a network is the
// designated when that equals its own GR port); uplink -> its designated GR
// port; and designated datapath -> the conditional MAC_Binding monitor cookie.
// Freshness propagates via MAC_Binding events (OVN's statctrl refreshes the
// designated's timestamp on data traffic), so no periodic scan is needed.
package macbinding

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"

	libovsdbcache "github.com/ovn-kubernetes/libovsdb/cache"
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/networkmanager"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

// keySep separates the designated port from the IP in a reconcile key.
// GR external port names never contain it.
const keySep = "|"

// networkRefReconcilerFunc adapts a function to the
// networkmanager.NetworkRefReconciler interface.
type networkRefReconcilerFunc func(node, networkName string)

func (f networkRefReconcilerFunc) Reconcile(node, networkName string) { f(node, networkName) }

// MACBindingController mirrors a designated Gateway Router's SB MAC_Binding
// entries onto the target Gateway Routers sharing its uplink. One per node.
type MACBindingController struct {
	sbClient       libovsdbclient.Client
	networkManager networkmanager.Interface
	watchFactory   factory.NodeWatchFactory
	syncOps        macBindingSyncOps

	nodeName       string
	ipv4Enabled    bool
	ipv6Enabled    bool
	cdnGatewayPort string

	mu sync.RWMutex
	// followers maps a source to follower GR port names that are being tracked
	followers map[string]sets.Set[string]
	// ports maps networks to GR port names that are being tracked
	ports map[string]string
	// monitorCookies maps datapath UUID to monitor cookie
	monitorCookies map[string]libovsdbclient.MonitorCookie

	macBindingReconciler controller.Reconciler
	networkReconciler    controller.Reconciler
}

// NewMACBindingController creates a new MACBindingController.
func NewMACBindingController(
	sbClient libovsdbclient.Client,
	networkManager networkmanager.Interface,
	watchFactory factory.NodeWatchFactory,
	nodeName string,
	ipv4Enabled bool,
	ipv6Enabled bool,
) *MACBindingController {
	c := &MACBindingController{
		sbClient:       sbClient,
		networkManager: networkManager,
		watchFactory:   watchFactory,
		syncOps:        newMACBindingSyncOps(sbClient),
		nodeName:       nodeName,
		ipv4Enabled:    ipv4Enabled,
		ipv6Enabled:    ipv6Enabled,
		cdnGatewayPort: types.GWRouterToExtSwitchPrefix + (&util.DefaultNetInfo{}).GetNetworkScopedGWRouterName(nodeName),
		followers:      map[string]sets.Set[string]{},
		ports:          map[string]string{},
		monitorCookies: map[string]libovsdbclient.MonitorCookie{},
	}
	c.macBindingReconciler = controller.NewReconciler(
		"mac-binding-reconciler",
		&controller.ReconcilerConfig{
			RateLimiter: controller.DefaultRateLimiter[string](),
			Reconcile:   c.reconcile,
			Threadiness: 1,
			MaxAttempts: 11, // with default rate limiter, retry during ~10s
		},
	)
	c.networkReconciler = controller.NewReconciler(
		"mac-binding-network-reconciler",
		&controller.ReconcilerConfig{
			Reconcile:   c.reconcileNetwork,
			Threadiness: 1,
			MaxAttempts: controller.InfiniteAttempts,
		},
	)
	return c
}

func (c *MACBindingController) ipEnabled(ip string) bool {
	if utilnet.IsIPv6String(ip) {
		return c.ipv6Enabled
	}
	return c.ipv4Enabled
}

// Run starts the controller and blocks until stopCh is closed.
func (c *MACBindingController) Run(stopCh <-chan struct{}) error {
	klog.Info("Running MAC Binding controller...")

	c.networkManager.RegisterNetworkRefReconciler(networkRefReconcilerFunc(func(node, networkName string) {
		if node != c.nodeName {
			return
		}
		for _, nadKey := range c.networkManager.GetNADKeysForNetwork(networkName) {
			c.networkReconciler.Reconcile(nadKey)
		}
	}))
	c.networkManager.RegisterNADReconciler(c.networkReconciler)

	// TODO register a single event handler for all tables and filter by table
	// name, instead of one per table
	c.registerMACBindingEventHandler()
	c.registerPortEventHandler()
	c.registerDataPathBindingEventHandler()
	
	if err := controller.Start(c.macBindingReconciler, c.networkReconciler); err != nil {
		return err
	}
	defer controller.Stop(c.macBindingReconciler, c.networkReconciler)

	<-stopCh
	klog.Info("Stopping MAC Binding controller...")
	return nil
}

// registerMACBindingEventHandler enqueues a mirror whenever a designated port's
// MAC_Binding row is added or updated. Deletes are ignored: target entries age
// out naturally.
func (c *MACBindingController) registerMACBindingEventHandler() {
	handle := func(table string, m model.Model) {
		if table != sbdb.MACBindingTable {
			return
		}
		mb := m.(*sbdb.MACBinding)
		if !c.ipEnabled(mb.IP) {
			return
		}
		if !c.tracksSource(mb.LogicalPort) {
			return
		}
		c.enqueue(mb.LogicalPort + keySep + mb.IP)
	}
	c.sbClient.Cache().AddEventHandler(&libovsdbcache.EventHandlerFuncs{
		AddFunc: func(table string, m model.Model) {
			handle(table, m)
		},
		UpdateFunc: func(table string, _ model.Model, new model.Model) {
			handle(table, new)
		},
	})
}

func (c *MACBindingController) registerDataPathBindingEventHandler() {
	c.sbClient.Cache().AddEventHandler(&libovsdbcache.EventHandlerFuncs{
		DeleteFunc: func(table string, m model.Model) {
			if table != sbdb.DatapathBindingTable {
				return
			}
			dp := m.(*sbdb.DatapathBinding)
			c.cancelMonitorForDatapath(dp.UUID)
		},
	})
}

// registerPortEventHandler cancels a designated's monitor when its datapath's
// PortBinding is deleted.
func (c *MACBindingController) registerPortEventHandler() {
	getPortBinding := func(table string, m model.Model) *sbdb.PortBinding {
		if table != sbdb.PortBindingTable {
			return nil
		}
		return m.(*sbdb.PortBinding)
	}
	isTracked := func(pb *sbdb.PortBinding) bool {
		network := pb.ExternalIDs[types.NetworkExternalID]
		if network == "" {
			return false
		}
		topology := pb.ExternalIDs[types.TopologyExternalID]
		if !shouldTrackTopology(topology) {
			return false
		}
		if !strings.HasPrefix(pb.LogicalPort, types.GWRouterToExtSwitchPrefix) && pb.Type != "localnet" {
			return false
		}
		return true
	}
	isUp := func(pb *sbdb.PortBinding) bool {
		return pb.Up != nil && *pb.Up
	}
	c.sbClient.Cache().AddEventHandler(&libovsdbcache.EventHandlerFuncs{
		AddFunc: func(table string, m model.Model) {
			pb := getPortBinding(table, m)
			if !isTracked(pb) || !isUp(pb) {
				return
			}
			network := pb.ExternalIDs[types.NetworkExternalID]
			c.networkReconciler.Reconcile(network)
		},
		UpdateFunc: func(table string, old model.Model, new model.Model) {
			newPB := getPortBinding(table, new)
			if !isTracked(newPB) {
				return
			}
			oldPB := getPortBinding(table, old)
			if isUp(oldPB) == isUp(newPB) {
				return
			}
			network := newPB.ExternalIDs[types.NetworkExternalID]
			if isUp(newPB) || c.removePort(network) {
				c.networkReconciler.Reconcile(network)
			}
		},
		DeleteFunc: func(table string, m model.Model) {
			pb := getPortBinding(table, m)
			if !isTracked(pb) || !isUp(pb) {
				return
			}
			network := pb.ExternalIDs[types.NetworkExternalID]
			if !c.removePort(network) {
				return
			}
			c.networkReconciler.Reconcile(network)
		},
	})
}

func (c *MACBindingController) cancelMonitorForDatapath(datapath string) {
	if datapath == "" {
		return
	}
	c.mu.Lock()
	cookie := c.monitorCookies[datapath]
	delete(c.monitorCookies, datapath)
	c.mu.Unlock()
	go func() {
		// TODO retrty unless "unknown monitor" error
		if err := c.sbClient.MonitorCancel(context.Background(), cookie); err != nil {
			klog.Warningf("MAC Binding controller failed to cancel monitor for datapath %s: %v", datapath, err)
		}
	}()
}

func (c *MACBindingController) enqueue(keys ...string) {
	for _, key := range keys {
		c.macBindingReconciler.Reconcile(key)
	}
}

func parseKey(key string) (designatedPort, ip string) {
	designatedPort, ip, _ = strings.Cut(key, keySep)
	return designatedPort, ip
}

// reconcile mirrors either a single (designated, ip) binding or, when no IP is
// given, all of a designated's bindings.
func (c *MACBindingController) reconcile(key string) error {
	port, ip := parseKey(key)
	if ip == "" {
		return c.reconcileMacBindingsForFollower(port)
	}
	return c.reconcileMacBindingsFromSourceForIP(port, ip)
}

// reconcileMacBindingsFromSourceForIP mirrors the designated's (ip, mac) onto every target port.
func (c *MACBindingController) reconcileMacBindingsFromSourceForIP(source, ip string) error {
	followers := c.getFollowers(source)
	if len(followers) == 0 {
		return nil
	}

	mb := &sbdb.MACBinding{LogicalPort: source, IP: ip}
	err := c.sbClient.Get(context.Background(), mb)
	if errors.Is(err, libovsdbclient.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	klog.V(5).Infof("MAC Binding controller mirroring %s -> %s from %s to %d folowers(s)", ip, mb.MAC, source, len(followers))
	return c.reconcileMacBindings(source, map[string]string{mb.IP: mb.MAC}, followers)
}

func (c *MACBindingController) reconcileMacBindingsForFollower(follower string) error {
	source := c.getSourceForFollower(follower)
	if source == "" {
		return nil
	}
	var macBindings map[string]string
	noop := []sbdb.MACBinding{}
	err := c.sbClient.WhereCache(func(mb *sbdb.MACBinding) bool {
		if mb.LogicalPort == source || !c.ipEnabled(mb.IP) {
			return false
		}
		macBindings[mb.IP] = mb.MAC
		return false
	}).List(context.Background(), &noop)
	if err != nil {
		return err
	}
	klog.V(5).Infof("MAC Binding controller mirroring %d IPs from %s to folowers %s", len(macBindings), source, follower)
	return c.reconcileMacBindings(source, macBindings, []string{follower})
}

func (c *MACBindingController) reconcileMacBindings(source string, macBindings map[string]string, followers []string) error {
	var portsInfos []portInfo
	for _, follower := range followers {
		if source == follower {
			continue
		}
		pb, err := ops.GetPortBinding(c.sbClient, &sbdb.PortBinding{LogicalPort: follower})
		if errors.Is(err, libovsdbclient.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if pb.Datapath == "" {
			continue
		}
		portsInfos = append(portsInfos, portInfo{LogicalPort: follower, DatapathUUID: pb.Datapath})
	}
	if len(portsInfos) == 0 {
		return nil
	}
	nowMs := int(time.Now().UnixMilli())
	return c.syncOps.SetMACBindings(macBindings, nowMs, portsInfos)
}

// reconcileNetwork reacts to a NAD change. When the network still resolves, its
// uplink tells us which group to update; when it is gone we cannot tell, so a
// GC sweep re-checks every tracked network.
func (c *MACBindingController) reconcileNetwork(key string) error {
	if key == "" {
		return c.reconcileAllNetworks()
	}

	netInfo := c.networkManager.GetNetInfoForNADKey(key)
	if netInfo == nil {
		netInfo = c.networkManager.GetNetwork(key)
	}
	if netInfo != nil && c.tracksNetwork(netInfo.GetNetworkName()) {
		// already aware, noop
		return nil
	}

	// full reconcile, queued to dedup
	c.networkReconciler.Reconcile("")
	return nil
}

func (c *MACBindingController) reconcileAllNetworks() error {
	knownPorts := sets.New[string]()
	portToUplink := map[string]string{}
	err := c.networkManager.DoWithLock(func(network util.NetInfo) error {
		if !shouldTrackNetwork(network) {
			return nil
		}
		port := types.GWRouterToExtSwitchPrefix + network.GetNetworkScopedGWRouterName(c.nodeName)
		knownPorts.Insert(port)
		portToUplink[port] = network.Uplink()
		return nil
	})
	if err != nil {
		return err
	}

	// handle removals
	validPorts := c.getPorts()
	validPorts = validPorts.Intersection(knownPorts)
	followers := c.getAllFollowers()
	unknownFollowers := followers.Difference(validPorts)
	if unknownFollowers.Len() > 0 {
		klog.V(5).Infof("Stopped tracking followers: %v", unknownFollowers.UnsortedList())
		c.removeFollowers(unknownFollowers)
	}

	// handle additions
	newPorts := knownPorts.Difference(validPorts)
	if newPorts.Len() == 0 {
		return nil
	}
	// TODO validate newPorts networks: both the GR and external ports must be up
	updatedSources := c.addFollowers(newPorts, portToUplink)
	for _, source := range updatedSources.UnsortedList() {
		err := c.handleSource(source)
		if err != nil {
			return err
		}
	}
	for newPort := range newPorts {
		c.enqueue(newPort)
	}

	return nil
}

// shouldTrackNetwork reports whether a network takes part in MAC binding mirroring:
// a primary L2/L3 network present on this node.
func shouldTrackNetwork(netInfo util.NetInfo) bool {
	if netInfo == nil || !netInfo.IsPrimaryNetwork() || !shouldTrackTopology(netInfo.TopologyType()) {
		return false
	}
	if netInfo.Uplink() != "" {
		// TODO add support for uplinks
		return false
	}
	return true
}

func shouldTrackTopology(topology string) bool {
	return topology == types.Layer2Topology || topology == types.Layer3Topology
}

func (c *MACBindingController) tracksNetwork(network string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ports[network] != ""
}

func (c *MACBindingController) tracksSource(source string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.followers[source] != nil
}

func (c *MACBindingController) getPorts() sets.Set[string] {
	c.mu.RLock()
	defer c.mu.RUnlock()
	portSet := sets.New[string]()
	for port := range c.ports {
		portSet.Insert(port)
	}
	return portSet
}

func (c *MACBindingController) removePort(network string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.ports[network]; !exists {
		return false
	}
	delete(c.ports, network)
	return true
}

func (c *MACBindingController) getAllFollowers() sets.Set[string] {
	c.mu.RLock()
	defer c.mu.RUnlock()
	followerSet := sets.New[string]()
	for source, followers := range c.followers {
		followers.Delete(source)
		followerSet.Union(followers)
	}
	return followerSet
}

func (c *MACBindingController) getFollowers(source string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	followers := c.followers[source]
	if followers == nil {
		return nil
	}
	return followers.UnsortedList()
}

func (c *MACBindingController) getSourceForFollower(follower string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for source, followers := range c.followers {
		if followers.Has(follower) {
			return source
		}
	}
	return ""
}

func (c *MACBindingController) removeFollowers(ports sets.Set[string]) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for source, followers := range c.followers {
		c.followers[source] = followers.Difference(ports)
		if c.followers[source].Len() == 0 {
			delete(c.followers, source)
		}
	}
	for port := range ports {
		delete(c.ports, port)
	}
}

func (c *MACBindingController) addFollowers(newPorts sets.Set[string], portToUplink map[string]string) sets.Set[string] {
	newPortsByUplink := map[string][]string{}
	for port := range newPorts {
		uplink := portToUplink[port]
		newPortsByUplink[uplink] = append(newPortsByUplink[uplink], port)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	updatedSources := sets.New[string]()
	for source, followers := range c.followers {
		uplink := portToUplink[source]
		if len(newPortsByUplink[uplink]) == 0 {
			continue
		}
		followers.Insert(newPortsByUplink[uplink]...)
		delete(newPortsByUplink, uplink)
		updatedSources.Insert(source)
	}
	for uplink, ports := range newPortsByUplink {
		if len(ports) < 2 {
			continue
		}
		source := ports[0]
		if uplink == "" {
			source = c.cdnGatewayPort
		}
		c.followers[source] = sets.New[string](ports...)
		updatedSources.Insert(source)
	}
	return updatedSources
}

func (c *MACBindingController) handleSource(source string) error {
	if source != c.cdnGatewayPort {
		// TODO add support for uplinkss: we would need to check if the curent
		// source is the oldest available and switch if not
		return nil
	}

	err := c.monitor(source, "")
	if err != nil {
		return err
	}
	return nil
}

func (c *MACBindingController) isDatapathMonitored(datapath string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.monitorCookies[datapath]
	return exists
}

func (c *MACBindingController) monitor(port, datapath string) error {
	if c.isDatapathMonitored(datapath) {
		return nil
	}
	var monitors []libovsdbclient.MonitorOption

	mb := sbdb.MACBinding{}
	monitors = append(monitors, libovsdbclient.WithConditionalTable(&mb,
		[]model.Condition{
			{
				Field:    &mb.LogicalPort,
				Function: ovsdb.ConditionEqual,
				Value:    port,
			},
		},
		&mb.LogicalPort, &mb.IP, &mb.MAC, &mb.Timestamp, &mb.Datapath),
	)

	if datapath != "" {
		db := sbdb.DatapathBinding{}
		monitors = append(monitors, libovsdbclient.WithConditionalTable(&mb,
			[]model.Condition{
				{
					Field:    &mb.Datapath,
					Function: ovsdb.ConditionEqual,
					Value:    datapath,
				},
			},
			&db.UUID),
		)
	}
	cookie, err := c.sbClient.Monitor(context.Background(), c.sbClient.NewMonitor(monitors...))
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.monitorCookies[datapath] = cookie
	return nil
}
