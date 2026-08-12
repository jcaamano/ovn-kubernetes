// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package macbinding

import (
	"context"
	"errors"
	"sync"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/util/sets"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	ovncnitypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/networkmanager"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
	libovsdbtest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
)

// mockSyncOps records SetMACBindings calls for assertions.
type mockSyncOps struct {
	mu    sync.Mutex
	calls []syncCall
}

type syncCall struct {
	ip        string
	mac       string
	timestamp int
	ports     []portInfo
}

func (m *mockSyncOps) SetMACBindings(bindings map[string]string, timestamp int, ports []portInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for ip, mac := range bindings {
		m.calls = append(m.calls, syncCall{ip: ip, mac: mac, timestamp: timestamp, ports: ports})
	}
	return nil
}

func (m *mockSyncOps) getCalls() []syncCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]syncCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// recorder is a sink for the reconcile keys a controller.Reconciler receives, so
// tests can assert which follow-up work the controller enqueued.
type recorder struct {
	mu   sync.Mutex
	keys []string
}

func (r *recorder) record(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, key)
}

func (r *recorder) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.keys))
	copy(out, r.keys)
	return out
}

// startRecorder builds a real controller.Reconciler whose only job is to record
// the keys it is handed (controller.Reconciler has unexported methods, so it
// cannot be faked outside the package). The caller must controller.Stop it.
func startRecorder(g gomega.Gomega, name string) (*recorder, controller.Reconciler) {
	rec := &recorder{}
	r := controller.NewReconciler(name, &controller.ReconcilerConfig{
		RateLimiter: controller.DefaultRateLimiter[string](),
		Reconcile:   func(key string) error { rec.record(key); return nil },
		Threadiness: 1,
		MaxAttempts: 1,
	})
	g.Expect(controller.Start(r)).To(gomega.Succeed())
	return rec, r
}

// cdnPortFor returns the CDN Gateway Router external port name for a node, the
// same way the controller derives it.
func cdnPortFor(node string) string {
	return types.GWRouterToExtSwitchPrefix + (&util.DefaultNetInfo{}).GetNetworkScopedGWRouterName(node)
}

// newTestController builds a controller wired only with the fields the
// method-level tests exercise, bypassing NewMACBindingController (which needs a
// live networkManager and watchFactory).
func newTestController(syncOps macBindingSyncOps) *MACBindingController {
	return &MACBindingController{
		syncOps:     syncOps,
		nodeName:    "node1",
		ipv4Enabled: true,
		followers:   map[string]sets.Set[string]{},
		ports:       map[string]string{},
		cookies:     map[string]libovsdbclient.MonitorCookie{},
	}
}

func TestIPFamilyEnabled(t *testing.T) {
	g := gomega.NewWithT(t)
	c := &MACBindingController{ipv4Enabled: true, ipv6Enabled: false}
	g.Expect(c.ipFamilyEnabled("10.0.0.5")).To(gomega.BeTrue())
	g.Expect(c.ipFamilyEnabled("fd00::5")).To(gomega.BeFalse())

	c = &MACBindingController{ipv4Enabled: false, ipv6Enabled: true}
	g.Expect(c.ipFamilyEnabled("10.0.0.5")).To(gomega.BeFalse())
	g.Expect(c.ipFamilyEnabled("fd00::5")).To(gomega.BeTrue())
}

// TestReconcileMacBindingsFromSourceForIP verifies the mirror read path: given a
// designated source MAC_Binding and a follower Gateway Router port,
// reconcileMacBindingsFromSourceForIP resolves the follower datapath and mirrors
// the (ip, mac) pair onto it.
func TestReconcileMacBindingsFromSourceForIP(t *testing.T) {
	g := gomega.NewWithT(t)

	const (
		cdnPort    = "rtoe-GR_node1"
		targetPort = "rtoe-GR_udn_node1"
		srcIP      = "10.0.0.5"
		srcMAC     = "0a:00:00:00:00:05"
	)

	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "src-dp"},
			&sbdb.DatapathBinding{UUID: "tgt-dp"},
			&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "src-dp"},
			&sbdb.PortBinding{UUID: "tgt-pb", LogicalPort: targetPort, Datapath: "tgt-dp"},
			&sbdb.MACBinding{UUID: "src-mb", LogicalPort: cdnPort, IP: srcIP, MAC: srcMAC, Datapath: "src-dp", Timestamp: 100},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	mock := &mockSyncOps{}
	c := newTestController(mock)
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPort
	c.followers[cdnPort] = sets.New(targetPort)

	// The static all-matching MAC_Binding monitor was removed, so the source row
	// only reaches the cache once the controller establishes its own monitor.
	g.Expect(c.ensureMonitor(cdnPort)).To(gomega.Succeed())

	tgtPB, err := ops.GetPortBinding(sbClient, &sbdb.PortBinding{LogicalPort: targetPort})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Expect(c.reconcileMacBindingsFromSourceForIP(cdnPort, srcIP)).To(gomega.Succeed())

	calls := mock.getCalls()
	g.Expect(calls).To(gomega.HaveLen(1))
	g.Expect(calls[0].ip).To(gomega.Equal(srcIP))
	g.Expect(calls[0].mac).To(gomega.Equal(srcMAC))
	g.Expect(calls[0].ports).To(gomega.ConsistOf(portInfo{LogicalPort: targetPort, DatapathUUID: tgtPB.Datapath}))
}

// TestReconcileMacBindingsFromSourceForIPNoSource confirms a missing source
// binding is a no-op: followers are left to age out rather than being cleared.
func TestReconcileMacBindingsFromSourceForIPNoSource(t *testing.T) {
	g := gomega.NewWithT(t)

	const cdnPort = "rtoe-GR_node1"

	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "cdn-dp"},
			&sbdb.DatapathBinding{UUID: "tgt-dp"},
			&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "cdn-dp"},
			&sbdb.PortBinding{UUID: "tgt-pb", LogicalPort: "rtoe-GR_udn_node1", Datapath: "tgt-dp"},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	mock := &mockSyncOps{}
	c := newTestController(mock)
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPort
	c.followers[cdnPort] = sets.New("rtoe-GR_udn_node1")

	g.Expect(c.ensureMonitor(cdnPort)).To(gomega.Succeed())
	g.Expect(c.reconcileMacBindingsFromSourceForIP(cdnPort, "10.0.0.9")).To(gomega.Succeed())
	g.Expect(mock.getCalls()).To(gomega.BeEmpty())
}

// TestReconcileMacBindingsForFollower verifies the follower catch-up path: a
// newly added follower gets every current source binding mirrored onto it.
func TestReconcileMacBindingsForFollower(t *testing.T) {
	g := gomega.NewWithT(t)

	const (
		cdnPort    = "rtoe-GR_node1"
		targetPort = "rtoe-GR_udn_node1"
	)

	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "src-dp"},
			&sbdb.DatapathBinding{UUID: "tgt-dp"},
			&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "src-dp"},
			&sbdb.PortBinding{UUID: "tgt-pb", LogicalPort: targetPort, Datapath: "tgt-dp"},
			&sbdb.MACBinding{UUID: "mb1", LogicalPort: cdnPort, IP: "10.0.0.5", MAC: "0a:00:00:00:00:05", Datapath: "src-dp", Timestamp: 100},
			&sbdb.MACBinding{UUID: "mb2", LogicalPort: cdnPort, IP: "10.0.0.6", MAC: "0a:00:00:00:00:06", Datapath: "src-dp", Timestamp: 100},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	mock := &mockSyncOps{}
	c := newTestController(mock)
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPort
	c.followers[cdnPort] = sets.New(targetPort)

	g.Expect(c.ensureMonitor(cdnPort)).To(gomega.Succeed())
	g.Expect(c.reconcileMacBindingsForFollower(targetPort)).To(gomega.Succeed())

	calls := mock.getCalls()
	g.Expect(calls).To(gomega.HaveLen(2))
	got := map[string]string{}
	for _, c := range calls {
		got[c.ip] = c.mac
		g.Expect(c.ports).To(gomega.ConsistOf(portInfo{LogicalPort: targetPort, DatapathUUID: calls[0].ports[0].DatapathUUID}))
	}
	g.Expect(got).To(gomega.Equal(map[string]string{
		"10.0.0.5": "0a:00:00:00:00:05",
		"10.0.0.6": "0a:00:00:00:00:06",
	}))
}

// TestSetMACBindings verifies the actual SB write path: SetMACBindings creates
// (and replaces) a MAC_Binding row for each follower port.
func TestSetMACBindings(t *testing.T) {
	g := gomega.NewWithT(t)

	const (
		targetPort = "rtoe-GR_udn_node1"
		ip         = "10.0.0.7"
		mac        = "0a:00:00:00:00:07"
	)

	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "tgt-dp"},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	// The static all-matching MAC_Binding monitor was removed, so the client no
	// longer caches MAC_Binding rows by default. Establish a monitor scoped to
	// the target port so the written rows reach the cache and the cache-backed
	// assertions below can observe them.
	_, err = sbClient.Monitor(context.Background(), sbClient.NewMonitor(macBindingMonitorFor(targetPort)))
	g.Expect(err).NotTo(gomega.HaveOccurred())

	// The harness no longer monitors DatapathBinding by default; opt in so the
	// seeded datapath can be resolved from the cache below.
	g.Expect(libovsdbtest.MonitorDatapathBindings(sbClient)).To(gomega.Succeed())

	// Resolve the real datapath UUID assigned by the server.
	var dps []*sbdb.DatapathBinding
	g.Expect(sbClient.List(context.Background(), &dps)).To(gomega.Succeed())
	g.Expect(dps).To(gomega.HaveLen(1))
	dpUUID := dps[0].UUID

	syncOps := newMACBindingSyncOps(sbClient)
	g.Expect(syncOps.SetMACBindings(map[string]string{ip: mac}, 200, []portInfo{{LogicalPort: targetPort, DatapathUUID: dpUUID}})).To(gomega.Succeed())

	g.Eventually(sbClient).Should(libovsdbtest.HaveDataSubset(
		&sbdb.MACBinding{LogicalPort: targetPort, IP: ip, MAC: mac, Datapath: dpUUID, Timestamp: 200},
	))

	// A second write with a newer timestamp replaces the row rather than
	// duplicating it.
	g.Expect(syncOps.SetMACBindings(map[string]string{ip: "0a:00:00:00:00:99"}, 300, []portInfo{{LogicalPort: targetPort, DatapathUUID: dpUUID}})).To(gomega.Succeed())
	g.Eventually(func(g gomega.Gomega) {
		var mbs []*sbdb.MACBinding
		g.Expect(sbClient.List(context.Background(), &mbs)).To(gomega.Succeed())
		g.Expect(mbs).To(gomega.HaveLen(1))
		g.Expect(mbs[0].MAC).To(gomega.Equal("0a:00:00:00:00:99"))
		g.Expect(mbs[0].Timestamp).To(gomega.Equal(300))
	}).Should(gomega.Succeed())
}

// --- allocation engine ---------------------------------------------------

// primaryUDN builds a primary Layer2 UDN NetInfo for allocation tests.
func primaryUDN(g gomega.Gomega, name, nadKey string) util.NetInfo {
	ni, err := util.NewNetInfo(&ovncnitypes.NetConf{
		NetConf:  cnitypes.NetConf{Name: name, Type: "ovn-k8s-cni-overlay"},
		Role:     types.NetworkRolePrimary,
		Topology: types.Layer2Topology,
		NADName:  nadKey,
		Subnets:  "192.168.0.0/16",
		MTU:      1400,
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	return ni
}

// TestReconcileNetworksDefaultGroup drives a full reconcile with the CDN plus a
// single primary L2 UDN present on the node. The CDN is designated the source
// and the UDN's GR external port becomes its follower; the new source is
// enqueued for monitoring.
func TestReconcileNetworksDefaultGroup(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())

	udn := primaryUDN(g, "tenantred", "ns1/nad1")
	cdnPort := cdnPortFor("node1")
	udnPort := types.GWRouterToExtSwitchPrefix + udn.GetNetworkScopedGWRouterName("node1")

	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "cdn-dp"},
			&sbdb.DatapathBinding{UUID: "udn-dp"},
			&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "cdn-dp"},
			&sbdb.PortBinding{UUID: "udn-pb", LogicalPort: udnPort, Datapath: "udn-dp"},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	nm := &networkmanager.FakeNetworkManager{
		PrimaryNetworks: map[string]util.NetInfo{"ns1": udn},
		NADNetworks:     map[string]util.NetInfo{"ns1/nad1": udn},
	}

	monitorRec, monitorR := startRecorder(g, "monitor")
	defer controller.Stop(monitorR)
	mbRec, mbR := startRecorder(g, "mb")
	defer controller.Stop(mbR)

	c := newTestController(&mockSyncOps{})
	c.sbClient = sbClient
	c.networkManager = nm
	c.cdnGatewayPort = cdnPort
	c.monitorReconciler = monitorR
	c.macBindingReconciler = mbR

	g.Expect(c.doReconcileNetworks()).To(gomega.Succeed())

	g.Expect(c.getFollowers(cdnPort)).To(gomega.ConsistOf(udnPort))
	g.Expect(c.tracksNetwork("tenantred")).To(gomega.BeTrue())
	// A brand new source is enqueued for monitoring, and its followers are
	// enqueued directly for catch-up.
	g.Eventually(monitorRec.got).Should(gomega.ConsistOf(cdnPort))
	g.Eventually(mbRec.got).Should(gomega.ConsistOf(udnPort))
}

// TestReconcileNetworkSkipsTrackedNetwork verifies that a NAD event for a
// network already tracked (and with no unknown-source followers pending) is a
// no-op.
func TestReconcileNetworkSkipsTrackedNetwork(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())

	udn := primaryUDN(g, "tenantred", "ns1/nad1")
	nm := &networkmanager.FakeNetworkManager{
		NADNetworks: map[string]util.NetInfo{"ns1/nad1": udn},
	}

	netRec, netR := startRecorder(g, "network")
	defer controller.Stop(netR)
	c := newTestController(&mockSyncOps{})
	c.networkManager = nm
	c.networkReconciler = netR
	c.ports["tenantred"] = "rtoe-GR_tenantred_node1"

	g.Expect(c.reconcileNetwork("ns1/nad1")).To(gomega.Succeed())
	g.Consistently(netRec.got).Should(gomega.BeEmpty())
}

// TestReconcileNetworkFullReconcileOnUnknownSource verifies that while any
// follower has an unknown source, every NAD event triggers a full reconcile so
// the controller can relocate it once the picture is complete.
func TestReconcileNetworkFullReconcileOnUnknownSource(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())

	udn := primaryUDN(g, "tenantred", "ns1/nad1")
	udnPort := types.GWRouterToExtSwitchPrefix + udn.GetNetworkScopedGWRouterName("node1")
	nm := &networkmanager.FakeNetworkManager{
		NADNetworks: map[string]util.NetInfo{"ns1/nad1": udn},
	}

	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "udn-dp"},
			&sbdb.PortBinding{UUID: "udn-pb", LogicalPort: udnPort, Datapath: "udn-dp"},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	netRec, netR := startRecorder(g, "network")
	defer controller.Stop(netR)
	c := newTestController(&mockSyncOps{})
	c.sbClient = sbClient
	c.networkManager = nm
	c.networkReconciler = netR
	c.followers["unknown"] = sets.New("rtoe-GR_other_node1")

	g.Expect(c.reconcileNetwork("ns1/nad1")).To(gomega.Succeed())
	g.Eventually(netRec.got).Should(gomega.ConsistOf(""))
}

// TestUpdateFollowersRemove verifies a follower whose port disappeared is
// dropped, and its now-empty source is removed.
func TestUpdateFollowersRemove(t *testing.T) {
	g := gomega.NewWithT(t)

	cdnPort := cdnPortFor("node1")
	udnPort := "rtoe-GR_tenantred_node1"

	c := newTestController(&mockSyncOps{})
	c.cdnGatewayPort = cdnPort
	c.followers[cdnPort] = sets.New(udnPort)
	c.ports["tenantred"] = udnPort

	newSources, newFollowers := c.updateFollowers(
		sets.New[string](), // addPorts
		sets.New(udnPort),  // removePorts
		map[string]string{cdnPort: ""},
		map[string]string{cdnPort: types.DefaultNetworkName},
		map[string]string{"": cdnPort},
	)

	g.Expect(newSources).To(gomega.BeEmpty())
	g.Expect(newFollowers).To(gomega.BeEmpty())
	g.Expect(c.getFollowers(cdnPort)).To(gomega.BeEmpty())
}

// TestUpdateFollowersUnknownSource verifies a port on an uplink with no known
// source is parked in the "unknown" bucket rather than dropped.
func TestUpdateFollowersUnknownSource(t *testing.T) {
	g := gomega.NewWithT(t)

	cdnPort := cdnPortFor("node1")
	udnPort := "rtoe-GR_tenantred_node1"

	c := newTestController(&mockSyncOps{})
	c.cdnGatewayPort = cdnPort

	newSources, newFollowers := c.updateFollowers(
		sets.New(udnPort),                       // addPorts
		sets.New[string](),                      // removePorts
		map[string]string{udnPort: "uplinkA"},   // portToUplink: uplinkA has no source
		map[string]string{udnPort: "tenantred"}, // portToNetwork
		map[string]string{"": cdnPort},          // uplinkToSource: only default group
	)

	g.Expect(newSources).To(gomega.BeEmpty())
	g.Expect(newFollowers).To(gomega.BeEmpty())
	g.Expect(c.hasUnknownSource()).To(gomega.BeTrue())
	g.Expect(c.getFollowers("unknown")).To(gomega.ConsistOf(udnPort))
	// The port is still recorded as known.
	g.Expect(c.tracksNetwork("tenantred")).To(gomega.BeTrue())
}

// --- monitor lifecycle ---------------------------------------------------

// TestEnsureMonitorCDN verifies establishing a monitor for the CDN source
// records a cookie and pulls that source's rows into the cache.
func TestEnsureMonitorCDN(t *testing.T) {
	g := gomega.NewWithT(t)

	cdnPort := cdnPortFor("node1")
	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "cdn-dp"},
			&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "cdn-dp"},
			&sbdb.MACBinding{UUID: "mb1", LogicalPort: cdnPort, IP: "10.0.0.5", MAC: "0a:00:00:00:00:05", Datapath: "cdn-dp", Timestamp: 100},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	c := newTestController(&mockSyncOps{})
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPort
	// ensureMonitor only acts on tracked sources.
	c.followers[cdnPort] = sets.New("rtoe-GR_udn_node1")

	// The CDN source is monitored under its resolved datapath UUID.
	cdnPB, err := ops.GetPortBinding(sbClient, &sbdb.PortBinding{LogicalPort: cdnPort})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	cdnDP := cdnPB.Datapath

	_, monitored := c.isDatapathMonitored(cdnDP)
	g.Expect(monitored).To(gomega.BeFalse())

	g.Expect(c.ensureMonitor(cdnPort)).To(gomega.Succeed())

	_, monitored = c.isDatapathMonitored(cdnDP)
	g.Expect(monitored).To(gomega.BeTrue())

	// The source row is now visible in the cache.
	mb := &sbdb.MACBinding{LogicalPort: cdnPort, IP: "10.0.0.5"}
	g.Expect(sbClient.Get(context.Background(), mb)).To(gomega.Succeed())
	g.Expect(mb.MAC).To(gomega.Equal("0a:00:00:00:00:05"))

	// Re-establishing is idempotent.
	g.Expect(c.ensureMonitor(cdnPort)).To(gomega.Succeed())
}

// TestReconcileMonitorEstablishes verifies that reconciling a source establishes
// its monitor. Follower catch-up is enqueued by doReconcileNetworks (and by the
// MAC_Binding event handler once source rows appear), not by reconcileMonitor.
func TestReconcileMonitorEstablishes(t *testing.T) {
	g := gomega.NewWithT(t)

	cdnPort := cdnPortFor("node1")
	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "cdn-dp"},
			&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "cdn-dp"},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	mbRec, mbR := startRecorder(g, "mb")
	defer controller.Stop(mbR)
	c := newTestController(&mockSyncOps{})
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPort
	c.macBindingReconciler = mbR
	c.followers[cdnPort] = sets.New("rtoe-GR_udn_node1")

	cdnPB, err := ops.GetPortBinding(sbClient, &sbdb.PortBinding{LogicalPort: cdnPort})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Expect(c.reconcileMonitor(cdnPort)).To(gomega.Succeed())

	_, monitored := c.isDatapathMonitored(cdnPB.Datapath)
	g.Expect(monitored).To(gomega.BeTrue())
	// reconcileMonitor only establishes the monitor; it does not enqueue followers.
	g.Consistently(mbRec.got).Should(gomega.BeEmpty())
}

// TestReconcileMonitorCancelsOnDatapathDelete verifies that reconcileMonitor
// routes a datapath that is currently monitored into the cancel path rather
// than the ensure path.
//
// The libovsdb test server does not implement monitor_cancel (server.go returns
// "not implemented"), and the client surfaces that error before touching any
// local state, so the successful teardown round-trip (cookie forgotten, monitor
// gone) cannot be exercised against the harness. We assert the routing instead:
// for a monitored datapath reconcileMonitor attempts MonitorCancel, whereas the
// ensure path would fail resolving the datapath UUID as a port with
// ErrNotFound.
func TestReconcileMonitorCancelsOnDatapathDelete(t *testing.T) {
	g := gomega.NewWithT(t)

	udnPort := "rtoe-GR_udn_node1"
	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "udn-dp"},
			&sbdb.PortBinding{UUID: "udn-pb", LogicalPort: udnPort, Datapath: "udn-dp"},
			&sbdb.MACBinding{UUID: "mb1", LogicalPort: udnPort, IP: "10.0.0.5", MAC: "0a:00:00:00:00:05", Datapath: "udn-dp", Timestamp: 100},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	udnPB, err := ops.GetPortBinding(sbClient, &sbdb.PortBinding{LogicalPort: udnPort})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	dpUUID := udnPB.Datapath

	c := newTestController(&mockSyncOps{})
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPortFor("node1")

	// Seed a monitor for a non-CDN source keyed by its datapath.
	cookie, err := c.sbClient.Monitor(context.Background(),
		c.sbClient.NewMonitor(macBindingMonitorFor(udnPort)))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	c.cookies[dpUUID] = cookie

	_, monitored := c.isDatapathMonitored(dpUUID)
	g.Expect(monitored).To(gomega.BeTrue())

	// reconcileMonitor takes the cancel branch: it attempts monitor_cancel
	// (unsupported by the test server) rather than the ensure branch (which
	// would fail with ErrNotFound resolving the datapath UUID as a port).
	err = c.reconcileMonitor(dpUUID)
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(errors.Is(err, libovsdbclient.ErrNotFound)).To(gomega.BeFalse())
}

// --- south-bound event handlers -----------------------------------------

// TestEventHandlers verifies the SB cache event handlers translate row changes
// into the right reconcile enqueues.
func TestEventHandlers(t *testing.T) {
	g := gomega.NewWithT(t)

	cdnPort := cdnPortFor("node1")
	udnPort := "rtoe-GR_tenantred_node1"

	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "cdn-dp"},
			&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "cdn-dp"},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	networkRec, networkR := startRecorder(g, "network")
	defer controller.Stop(networkR)
	mbRec, mbR := startRecorder(g, "mb")
	defer controller.Stop(mbR)
	monitorRec, monitorR := startRecorder(g, "monitor")
	defer controller.Stop(monitorR)
	c := newTestController(&mockSyncOps{})
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPort
	c.networkReconciler = networkR
	c.macBindingReconciler = mbR
	c.monitorReconciler = monitorR
	// track the CDN as a source so its MAC_Binding events are relevant.
	c.followers[cdnPort] = sets.New(udnPort)

	c.registerSouthBoundEventHandlers()

	// MAC_Binding is not monitored by default; establish the CDN source monitor
	// so its rows reach the cache and fire events.
	g.Expect(c.ensureMonitor(cdnPort)).To(gomega.Succeed())

	// A PortBinding for a primary L2 GR external port enqueues its network.
	// ContainElement (not ConsistOf) because the seeded CDN gateway PortBinding's
	// own add event legitimately enqueues a full re-eval ("") via
	// enqueueAllNetworks, and that arrives asynchronously.
	createRow(g, sbClient, &sbdb.PortBinding{
		LogicalPort: udnPort,
		ExternalIDs: map[string]string{
			types.NetworkExternalID:  "tenantred",
			types.TopologyExternalID: types.Layer2Topology,
		},
	})
	g.Eventually(networkRec.got).Should(gomega.ContainElement("tenantred"))

	// A MAC_Binding on the tracked CDN source enqueues designated|ip.
	createRow(g, sbClient, &sbdb.MACBinding{
		LogicalPort: cdnPort,
		IP:          "10.0.0.5",
		MAC:         "0a:00:00:00:00:05",
	})
	g.Eventually(mbRec.got).Should(gomega.ConsistOf(cdnPort + keySep + "10.0.0.5"))

	// Deleting a datapath enqueues it for monitor teardown. The CDN PortBinding
	// references the datapath, so both the referencing PortBinding(s) and the
	// datapath are removed in a single transaction to avoid a
	// referential-integrity violation (OVSDB checks integrity at
	// end-of-transaction).
	var dps []*sbdb.DatapathBinding
	g.Expect(sbClient.List(context.Background(), &dps)).To(gomega.Succeed())
	g.Expect(dps).To(gomega.HaveLen(1))
	dpUUID := dps[0].UUID
	pbDelOps, err := sbClient.WhereCache(func(pb *sbdb.PortBinding) bool {
		return pb.Datapath == dpUUID
	}).Delete()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	dpDelOps, err := sbClient.Where(dps[0]).Delete()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, err = ops.TransactAndCheck(sbClient, append(pbDelOps, dpDelOps...))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Eventually(monitorRec.got).Should(gomega.ConsistOf(dpUUID))
}

// --- small helpers -------------------------------------------------------

// macBindingMonitorFor builds a conditional MAC_Binding monitor scoped to a
// single logical port, matching what ensureMonitor installs for the CDN source.
func macBindingMonitorFor(port string) libovsdbclient.MonitorOption {
	mb := &sbdb.MACBinding{}
	return libovsdbclient.WithConditionalTable(mb,
		[]model.Condition{{Field: &mb.LogicalPort, Function: ovsdb.ConditionEqual, Value: port}},
		&mb.LogicalPort, &mb.IP, &mb.MAC, &mb.Timestamp, &mb.Datapath)
}

// createRow inserts a single row into the SB database.
func createRow(g gomega.Gomega, sbClient libovsdbclient.Client, m model.Model) {
	createOps, err := sbClient.Create(m)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, err = ops.TransactAndCheck(sbClient, createOps)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
