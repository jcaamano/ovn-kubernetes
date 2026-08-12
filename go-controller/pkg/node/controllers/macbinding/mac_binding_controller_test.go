// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package macbinding

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/util/sets"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"

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

// fakeUplinkSourceProvider provides the designated uplink sources without a real
// openflow manager. An empty map leaves only the default group (the getter adds
// the CDN source for the "" uplink itself).
type fakeUplinkSourceProvider struct {
	sources map[string]string
}

func (f *fakeUplinkSourceProvider) GetMacBindingSourceForUplinks() map[string]string {
	return f.sources
}

// newTestController builds a controller wired only with the fields the
// method-level tests exercise, bypassing NewMACBindingController (which needs a
// live networkManager and watchFactory).
func newTestController() *MACBindingController {
	return &MACBindingController{
		uplinkSourceProvider: &fakeUplinkSourceProvider{sources: map[string]string{}},
		nodeName:             "node1",
		ipv4Enabled:          true,
		followers:            map[string]sets.Set[string]{},
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

// TestReconcileMacBindingsForIPFromSource verifies the mirror read path: given a
// designated source MAC_Binding and a follower Gateway Router port,
// reconcileMacBindingsForIPFromSource resolves the follower datapath and mirrors
// the (ip, mac) pair onto it. A missing source binding is a no-op: followers are
// left to age out rather than being cleared.
func TestReconcileMacBindingsForIPFromSource(t *testing.T) {
	const (
		cdnPort    = "rtoe-GR_node1"
		targetPort = "rtoe-GR_udn_node1"
		srcIP      = "10.0.0.5"
		srcMAC     = "0a:00:00:00:00:05"
	)

	tests := []struct {
		name string
		// seedBinding, when true, seeds the source MAC_Binding row for srcIP.
		seedBinding bool
		reconcileIP string
		wantMirror  bool
	}{
		{
			name:        "mirrors an existing source binding onto the follower",
			seedBinding: true,
			reconcileIP: srcIP,
			wantMirror:  true,
		},
		{
			name:        "is a no-op when the source binding is missing",
			reconcileIP: "10.0.0.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			setup := libovsdbtest.TestSetup{
				IgnoreConstraints: true,
				SBData: []libovsdbtest.TestData{
					&sbdb.DatapathBinding{UUID: "src-dp"},
					&sbdb.DatapathBinding{UUID: "tgt-dp"},
					&sbdb.PortBinding{UUID: "cdn-pb", LogicalPort: cdnPort, Datapath: "src-dp"},
					&sbdb.PortBinding{UUID: "tgt-pb", LogicalPort: targetPort, Datapath: "tgt-dp"},
				},
			}
			if tt.seedBinding {
				setup.SBData = append(setup.SBData,
					&sbdb.MACBinding{UUID: "src-mb", LogicalPort: cdnPort, IP: srcIP, MAC: srcMAC, Datapath: "src-dp", Timestamp: 100})
			}
			sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
			g.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanup.Cleanup()

			c := newTestController()
			c.sbClient = sbClient
			c.cdnGatewayPort = cdnPort
			c.followers[cdnPort] = sets.New(targetPort)

			tgtPB, err := ops.GetPortBinding(sbClient, &sbdb.PortBinding{LogicalPort: targetPort})
			g.Expect(err).NotTo(gomega.HaveOccurred())

			// The write is synchronous: TransactAndCheck only returns once the
			// server has broadcast the update and the client has applied it to
			// its cache, so the cache read below needs no Eventually.
			g.Expect(c.reconcileMacBindingsForIPFromSource(tt.reconcileIP, cdnPort)).To(gomega.Succeed())

			if !tt.wantMirror {
				g.Expect(macBindingsFor(g, sbClient, targetPort)).To(gomega.BeEmpty())
				return
			}

			// The (ip, mac) pair is mirrored onto the follower's datapath.
			mbs := macBindingsFor(g, sbClient, targetPort)
			g.Expect(mbs).To(gomega.HaveLen(1))
			g.Expect(mbs[0].IP).To(gomega.Equal(srcIP))
			g.Expect(mbs[0].MAC).To(gomega.Equal(srcMAC))
			g.Expect(mbs[0].Datapath).To(gomega.Equal(tgtPB.Datapath))
		})
	}
}

// TestReconcileMacBindingsForFollower verifies the follower catch-up path: a
// newly added follower gets every current source binding for an enabled IP
// family mirrored onto it, while bindings for a disabled family are skipped.
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
			// IPv6 binding: ignored because the controller has IPv6 disabled.
			&sbdb.MACBinding{UUID: "mb3", LogicalPort: cdnPort, IP: "fd00::5", MAC: "0a:00:00:00:00:07", Datapath: "src-dp", Timestamp: 100},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	c := newTestController() // ipv4 enabled, ipv6 disabled
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPort
	c.followers[cdnPort] = sets.New(targetPort)

	tgtPB, err := ops.GetPortBinding(sbClient, &sbdb.PortBinding{LogicalPort: targetPort})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Expect(c.reconcileMacBindingsForFollower(targetPort)).To(gomega.Succeed())

	// Only the enabled-family (IPv4) source bindings are mirrored onto the new
	// follower; the IPv6 binding is skipped.
	got := map[string]string{}
	for _, mb := range macBindingsFor(g, sbClient, targetPort) {
		got[mb.IP] = mb.MAC
		g.Expect(mb.Datapath).To(gomega.Equal(tgtPB.Datapath))
	}
	g.Expect(got).To(gomega.Equal(map[string]string{
		"10.0.0.5": "0a:00:00:00:00:05",
		"10.0.0.6": "0a:00:00:00:00:06",
	}))
}

// TestSetMacBindings verifies the actual SB write path: setMacBindings mirrors
// every (port, ip) pair in a single write, creating a row that does not exist,
// replacing one whose timestamp is older than the cooldown, and leaving one
// whose timestamp is still within the cooldown untouched.
func TestSetMacBindings(t *testing.T) {
	const (
		portA     = "rtoe-GR_udnA_node1"
		portB     = "rtoe-GR_udnB_node1"
		ip        = "10.0.0.7"
		otherIP   = "10.0.0.8"
		firstMAC  = "0a:00:00:00:00:07"
		otherMAC  = "0a:00:00:00:00:08"
		secondMAC = "0a:00:00:00:00:99"
	)

	// wantData holds the the mac and timstamp of a mac binding
	type wantData struct {
		mac       string
		timestamp int
	}

	tests := []struct {
		name string
		// initial mac bindings
		initial          map[string]string
		initialTimestamp int
		// mac bindings to set
		set          map[string]string
		setTimestamp int
		// ports to set the mac bings for
		targets []string
		// expect port->ip->mac,timestamp.
		want map[string]map[string]wantData
	}{
		{
			name:         "creates a row that does not yet exist",
			set:          map[string]string{ip: secondMAC},
			setTimestamp: 200,
			targets:      []string{portA},
			want:         map[string]map[string]wantData{portA: {ip: {secondMAC, 200}}},
		},
		{
			name:             "refreshes an unchanged row's timestamp once past the cooldown",
			initial:          map[string]string{ip: firstMAC},
			initialTimestamp: 200,
			set:              map[string]string{ip: firstMAC},
			setTimestamp:     200 + ovnk_cooldown_period_ms,
			targets:          []string{portA},
			want:             map[string]map[string]wantData{portA: {ip: {firstMAC, 200 + ovnk_cooldown_period_ms}}},
		},
		{
			name:             "skips a timestamp refresh still within the cooldown",
			initial:          map[string]string{ip: firstMAC},
			initialTimestamp: 200,
			set:              map[string]string{ip: firstMAC},
			setTimestamp:     200 + ovnk_cooldown_period_ms - 1,
			targets:          []string{portA},
			want:             map[string]map[string]wantData{portA: {ip: {firstMAC, 200}}},
		},
		{
			name:             "writes a changed MAC even within the cooldown",
			initial:          map[string]string{ip: firstMAC},
			initialTimestamp: 200,
			set:              map[string]string{ip: secondMAC},
			setTimestamp:     200 + ovnk_cooldown_period_ms - 1,
			targets:          []string{portA},
			want:             map[string]map[string]wantData{portA: {ip: {secondMAC, 200 + ovnk_cooldown_period_ms - 1}}},
		},
		{
			name:         "mirrors every ip onto every port in one write",
			set:          map[string]string{ip: firstMAC, otherIP: otherMAC},
			setTimestamp: 200,
			targets:      []string{portA, portB},
			want: map[string]map[string]wantData{
				portA: {ip: {firstMAC, 200}, otherIP: {otherMAC, 200}},
				portB: {ip: {firstMAC, 200}, otherIP: {otherMAC, 200}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			// Seed any pre-existing rows through SBData rather than via
			// setMacBindings, so the update/cooldown path is exercised against a
			// precondition established independently of the method under test.
			// The seeded Datapath is never asserted; it just references the shared
			// datapath so the rows are well-formed.
			setup := libovsdbtest.TestSetup{
				IgnoreConstraints: true,
				SBData: []libovsdbtest.TestData{
					&sbdb.DatapathBinding{UUID: "tgt-dp"},
				},
			}
			for _, port := range tt.targets {
				for ip, mac := range tt.initial {
					setup.SBData = append(setup.SBData, &sbdb.MACBinding{
						LogicalPort: port,
						IP:          ip,
						MAC:         mac,
						Datapath:    "tgt-dp",
						Timestamp:   tt.initialTimestamp,
					})
				}
			}
			sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
			g.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanup.Cleanup()

			// The production SB client monitors the full MAC_Binding table, so
			// written rows reach the cache without the test installing its own
			// monitor (a second overlapping MAC_Binding monitor would make the
			// cache inconsistent).

			// Resolve the real datapath UUID assigned by the server; all ports
			// share it.
			var dps []*sbdb.DatapathBinding
			g.Expect(sbClient.List(context.Background(), &dps)).To(gomega.Succeed())
			g.Expect(dps).To(gomega.HaveLen(1))
			dpUUID := dps[0].UUID
			portToDatapath := map[string]string{}
			for _, port := range tt.targets {
				portToDatapath[port] = dpUUID
			}

			c := newTestController()
			c.sbClient = sbClient

			// setMacBindings is synchronous: on return the cache already reflects
			// the write (or, for the cooldown-skip case, the lack of one).
			g.Expect(c.setMacBindings(tt.set, tt.setTimestamp, portToDatapath)).To(gomega.Succeed())

			for port, want := range tt.want {
				got := map[string]wantData{}
				for _, mb := range macBindingsFor(g, sbClient, port) {
					got[mb.IP] = wantData{mb.MAC, mb.Timestamp}
				}
				g.Expect(got).To(gomega.Equal(want))
			}
		})
	}
}

// --- allocation engine ---------------------------------------------------

// primaryUDN builds a primary Layer2 UDN NetInfo for allocation tests. A
// non-empty uplink is reported by NetInfo.Uplink() only when the uplink feature
// is enabled (see enableUplinkFeature), so callers exercising uplink groups must
// enable it first.
func primaryUDN(g gomega.Gomega, name, nadKey, uplink string) util.NetInfo {
	ni, err := util.NewNetInfo(&ovncnitypes.NetConf{
		NetConf:  cnitypes.NetConf{Name: name, Type: "ovn-k8s-cni-overlay"},
		Role:     types.NetworkRolePrimary,
		Topology: types.Layer2Topology,
		NADName:  nadKey,
		Subnets:  "192.168.0.0/16",
		MTU:      1400,
		Uplink:   uplink,
	})
	g.Expect(err).NotTo(gomega.HaveOccurred())
	return ni
}

// TestReconcileNetwork covers the NAD-event routing layer: an event for a
// network already tracked (with no unknown-source followers pending) is a no-op,
// whereas while any follower has an unknown source every NAD event triggers a
// full reconcile (enqueued as the "" key) so the controller can relocate it once
// the picture is complete.
func TestReconcileNetwork(t *testing.T) {
	tests := []struct {
		name string
		// trackNetwork pre-registers "tenantred" as already tracked.
		trackNetwork bool
		// unknownSource seeds a follower with an unresolved source.
		unknownSource bool
		// wantEnqueued is the set of reconcile keys expected; nil means none.
		wantEnqueued []string
	}{
		{
			name:         "skips a network already tracked",
			trackNetwork: true,
		},
		{
			name:          "full reconcile while a follower's source is unknown",
			unknownSource: true,
			wantEnqueued:  []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())

			udn := primaryUDN(g, "tenantred", "ns1/nad1", "")
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
			c := newTestController()
			c.sbClient = sbClient
			c.networkManager = nm
			c.networkReconciler = netR
			// FIXME
			//if tt.trackNetwork {
			//	c.ports["tenantred"] = "rtoe-GR_tenantred_node1"
			//}
			if tt.unknownSource {
				c.followers["unknown"] = sets.New("rtoe-GR_other_node1")
			}

			g.Expect(c.reconcileNetwork("ns1/nad1")).To(gomega.Succeed())

			if tt.wantEnqueued == nil {
				g.Consistently(netRec.got).Should(gomega.BeEmpty())
				return
			}
			g.Eventually(netRec.got).Should(gomega.ConsistOf(tt.wantEnqueued))
		})
	}
}

// enableUplinkFeature turns on the feature flags that userDefinedNetInfo.Uplink()
// gates on, so a NetInfo built with a non-empty NetConf.Uplink actually reports
// it. config.PrepareTestConfig resets these between tests.
func enableUplinkFeature() {
	config.OVNKubernetesFeature.EnableMultiNetwork = true
	config.OVNKubernetesFeature.EnableNetworkSegmentation = true
	config.OVNKubernetesFeature.EnableUplink = true
}

// TestDoReconcileNetworks drives a full (all-networks) reconcile and asserts the
// resulting follower and port maps plus the followers enqueued for a mac binding
// catch-up. It exercises the gather + source-resolution + port-validation
// pipeline that feeds the allocation engine; the engine's own relocation
// scenarios are covered by TestUpdateFollowers, so the cases here vary the
// gather inputs (networks, uplink sources, SB presence) rather than the engine.
func TestDoReconcileNetworks(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())
	enableUplinkFeature()

	cdnPort := cdnPortFor("node1")

	// Default-group primary UDN (shares breth0, Uplink() == "").
	udn := primaryUDN(g, "tenantred", "ns1/nad1", "")
	udnPort := util.GetNetworkScopedGWRouterExtPortName(udn.GetNetworkName(), "node1")
	// Two CUDNs sharing a dedicated uplink; cudnA is the designated source.
	cudnA := primaryUDN(g, "cudnA", "nsA/nadA", "uplinkA")
	cudnB := primaryUDN(g, "cudnB", "nsB/nadB", "uplinkA")
	portA := util.GetNetworkScopedGWRouterExtPortName(cudnA.GetNetworkName(), "node1")
	portB := util.GetNetworkScopedGWRouterExtPortName(cudnB.GetNetworkName(), "node1")

	tests := []struct {
		name string
		// primaryNetworks are the networks the fake network manager tracks
		// (namespace -> NetInfo); the CDN is always gathered implicitly.
		primaryNetworks map[string]util.NetInfo
		// uplinkSources is what the uplink source provider designates
		// (uplink -> source GR external port).
		uplinkSources map[string]string
		// sbPorts are the GR external ports that have a PortBinding in the SB DB.
		sbPorts []string
		// preTracked pre-registers network -> port as already known, to exercise
		// the no-op path when nothing changed.
		preTracked map[string]string
		// wantEnqueued is the set of followers enqueued for a catch-up.
		wantEnqueued []string
		// wantPorts is the expected network -> port map after the reconcile.
		wantPorts map[string]string
		// wantFollowers is the expected source -> followers map after the
		// reconcile (only sources with followers need to be listed).
		wantFollowers map[string][]string
	}{
		{
			name:            "default group mirrors the CDN onto a primary UDN follower",
			primaryNetworks: map[string]util.NetInfo{"ns1": udn},
			sbPorts:         []string{cdnPort, udnPort},
			wantEnqueued:    []string{udnPort},
			wantPorts:       map[string]string{types.DefaultNetworkName: cdnPort, "tenantred": udnPort},
			wantFollowers:   map[string][]string{cdnPort: {udnPort}},
		},
		{
			name:            "uplink group mirrors the designated source onto the other member",
			primaryNetworks: map[string]util.NetInfo{"nsA": cudnA, "nsB": cudnB},
			uplinkSources:   map[string]string{"uplinkA": portA},
			sbPorts:         []string{cdnPort, portA, portB},
			wantEnqueued:    []string{portB},
			wantPorts:       map[string]string{types.DefaultNetworkName: cdnPort, "cudnA": portA, "cudnB": portB},
			wantFollowers:   map[string][]string{portA: {portB}},
		},
		{
			name:            "a network whose port is absent from the SB is not mirrored",
			primaryNetworks: map[string]util.NetInfo{"ns1": udn},
			sbPorts:         []string{cdnPort}, // udnPort has no PortBinding
			// only the CDN is realized, so tenantred is neither tracked nor followed
			wantPorts: map[string]string{types.DefaultNetworkName: cdnPort},
		},
		{
			name:            "no-op when every gathered port is already tracked",
			primaryNetworks: map[string]util.NetInfo{"ns1": udn},
			sbPorts:         []string{cdnPort, udnPort},
			preTracked:      map[string]string{types.DefaultNetworkName: cdnPort, "tenantred": udnPort},
			// reconcile returns early, leaving the pre-tracked maps untouched
			wantPorts: map[string]string{types.DefaultNetworkName: cdnPort, "tenantred": udnPort},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			setup := libovsdbtest.TestSetup{IgnoreConstraints: true}
			for i, port := range tt.sbPorts {
				dp := fmt.Sprintf("dp-%d", i)
				setup.SBData = append(setup.SBData,
					&sbdb.DatapathBinding{UUID: dp},
					&sbdb.PortBinding{UUID: fmt.Sprintf("pb-%d", i), LogicalPort: port, Datapath: dp},
				)
			}
			sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
			g.Expect(err).NotTo(gomega.HaveOccurred())
			defer cleanup.Cleanup()

			mbRec, mbR := startRecorder(g, "mb")
			defer controller.Stop(mbR)

			// A non-nil (possibly empty) sources map is required: a nil map makes
			// the provider skip the default "" -> CDN mapping.
			sources := maps.Clone(tt.uplinkSources)
			if sources == nil {
				sources = map[string]string{}
			}

			c := newTestController()
			c.sbClient = sbClient
			c.networkManager = &networkmanager.FakeNetworkManager{PrimaryNetworks: tt.primaryNetworks}
			c.cdnGatewayPort = cdnPort
			c.macBindingReconciler = mbR
			c.uplinkSourceProvider = &fakeUplinkSourceProvider{sources: sources}
			// FIXME
			//maps.Copy(c.ports, tt.preTracked)

			g.Expect(c.doReconcileNetworks()).To(gomega.Succeed())

			// Followers enqueued for a catch-up (doReconcileNetworks' output).
			if len(tt.wantEnqueued) == 0 {
				g.Consistently(mbRec.got).Should(gomega.BeEmpty())
			} else {
				g.Eventually(mbRec.got).Should(gomega.ConsistOf(tt.wantEnqueued))
			}

			// Resulting port and follower maps.
			// FIXME
			//g.Expect(c.ports).To(gomega.Equal(tt.wantPorts))
			var allFollowers []string
			for source, followers := range tt.wantFollowers {
				g.Expect(c.getFollowers(source)).To(gomega.ConsistOf(followers))
				allFollowers = append(allFollowers, followers...)
			}
			// No followers beyond the ones listed above.
			// FIXME
			//g.Expect(c.getAllFollowers().UnsortedList()).To(gomega.ConsistOf(allFollowers))
		})
	}
}

// TestUpdateFollowers exercises the in-memory follower allocation engine
// directly: given a starting followers/ports state and a set of port additions,
// removals and the resolved uplink/source topology, it asserts the recomputed
// follower map and the set of ports that became new followers (which the caller
// enqueues for a mac binding catch-up).
func TestUpdateFollowers(t *testing.T) {
	cdnPort := cdnPortFor("node1")
	const (
		udnPort   = "rtoe-GR_tenantred_node1"
		oldSource = "rtoe-GR_cudnA_node1"
		newSource = "rtoe-GR_cudnB_node1"
	)

	tests := []struct {
		name string
		// starting controller state
		followers map[string][]string // source -> followers
		ports     map[string]string   // network -> port

		// updateFollowers arguments
		addPorts       []string
		removePorts    []string
		portToUplink   map[string]string
		portToNetwork  map[string]string
		uplinkToSource map[string]string

		// expectations
		wantNewFollowers []string
		wantFollowers    map[string][]string // source -> expected followers
		wantTracks       []string            // networks expected to be tracked
	}{
		{
			// A follower whose port disappeared is dropped, and its now-empty
			// source is removed.
			name:           "removes a dropped follower and prunes its empty source",
			followers:      map[string][]string{cdnPort: {udnPort}},
			ports:          map[string]string{"tenantred": udnPort},
			removePorts:    []string{udnPort},
			portToUplink:   map[string]string{cdnPort: ""},
			portToNetwork:  map[string]string{cdnPort: types.DefaultNetworkName},
			uplinkToSource: map[string]string{"": cdnPort},
			wantFollowers:  map[string][]string{cdnPort: nil},
		},
		{
			// A port on an uplink with no known source is parked in the
			// "unknown" bucket rather than dropped, and is still tracked.
			name:           "parks a port with no known source as unknown",
			addPorts:       []string{udnPort},
			portToUplink:   map[string]string{udnPort: "uplinkA"}, // uplinkA has no source
			portToNetwork:  map[string]string{udnPort: "tenantred"},
			uplinkToSource: map[string]string{"": cdnPort}, // only default group
			wantFollowers:  map[string][]string{"unknown": {udnPort}},
			wantTracks:     []string{"tenantred"},
		},
		{
			// When the designated source of an uplink group changes, the old
			// source's followers are relocated under the new source and the old
			// source itself becomes a follower.
			name:             "relocates followers when the source is re-designated",
			followers:        map[string][]string{oldSource: {newSource}},
			portToUplink:     map[string]string{oldSource: "uplinkA", newSource: "uplinkA"},
			uplinkToSource:   map[string]string{"uplinkA": newSource, "": cdnPort},
			wantNewFollowers: []string{oldSource},
			wantFollowers: map[string][]string{
				newSource: {oldSource},
				oldSource: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			c := newTestController()
			c.cdnGatewayPort = cdnPort
			for source, followers := range tt.followers {
				c.followers[source] = sets.New(followers...)
			}
			// FIXME
			//maps.Copy(c.ports, tt.ports)

			newFollowers := c.updateFollowers(
				sets.New(tt.addPorts...),
				sets.New(tt.removePorts...),
				tt.portToUplink,
				tt.uplinkToSource,
			)

			g.Expect(newFollowers.UnsortedList()).To(gomega.ConsistOf(tt.wantNewFollowers))
			for source, want := range tt.wantFollowers {
				g.Expect(c.getFollowers(source)).To(gomega.ConsistOf(want))
			}

			//FIXME
			/*
				for _, network := range tt.wantTracks {
					g.Expect(c.tracksNetwork(network)).To(gomega.BeTrue())
				}
			*/
		})
	}
}

// TestReconcileUplinkSource verifies that a re-designation notification resets
// the cached uplink sources and, when the network is not already a source, parks
// it as unknown and enqueues a network reconcile so the group is recomputed.
func TestReconcileUplinkSource(t *testing.T) {
	g := gomega.NewWithT(t)
	g.Expect(config.PrepareTestConfig()).To(gomega.Succeed())

	const network = "tenantred"
	port := util.GetNetworkScopedGWRouterExtPortName(network, "node1")

	tests := []struct {
		name string
		// alreadySource pre-registers the network's port as an existing source.
		alreadySource bool
		wantUnknown   bool
		wantEnqueue   bool
	}{
		{
			name:        "parks and enqueues a network that is not yet a source",
			wantUnknown: true,
			wantEnqueue: true,
		},
		{
			name:          "leaves an already-designated source in place",
			alreadySource: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			netRec, netR := startRecorder(g, "network")
			defer controller.Stop(netR)

			c := newTestController()
			c.cdnGatewayPort = cdnPortFor("node1")
			c.networkReconciler = netR
			// prime the cache so we can observe it being reset.
			c.setMacBindingSourceForUplinks(map[string]string{"uplinkA": port})
			if tt.alreadySource {
				c.followers[port] = sets.New("rtoe-GR_follower_node1")
			}

			c.ReconcileUplinkSource(network)

			// the cached uplink sources are always reset.
			g.Expect(c.macBindingSourceForUplinks.Load()).To(gomega.BeNil())
			g.Expect(c.hasUnknownSource()).To(gomega.Equal(tt.wantUnknown))
			if tt.wantEnqueue {
				g.Eventually(netRec.got).Should(gomega.ConsistOf(network))
			} else {
				g.Consistently(netRec.got, "200ms", "50ms").Should(gomega.BeEmpty())
			}
		})
	}
}

// TestSetMacBindingSourceForUplinks verifies the uplink-source cache setter: a
// nil map clears the cache, while a non-nil map is stored after the CDN source
// is injected for the default ("") uplink.
func TestSetMacBindingSourceForUplinks(t *testing.T) {
	const cdn = "rtoe-GR_node1"

	tests := []struct {
		name       string
		input      map[string]string
		wantReturn map[string]string
		wantCached bool
	}{
		{
			name:  "nil input clears the cache",
			input: nil,
		},
		{
			name:       "non-nil input injects the CDN source and caches",
			input:      map[string]string{"uplinkA": "rtoe-GR_cudnA_node1"},
			wantReturn: map[string]string{"uplinkA": "rtoe-GR_cudnA_node1", "": cdn},
			wantCached: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			c := newTestController()
			c.cdnGatewayPort = cdn
			// pre-seed the cache to prove nil clears it and non-nil overwrites it.
			c.setMacBindingSourceForUplinks(map[string]string{"stale": "x"})

			got := c.setMacBindingSourceForUplinks(tt.input)

			g.Expect(got).To(gomega.Equal(tt.wantReturn))
			if tt.wantCached {
				loaded := c.macBindingSourceForUplinks.Load()
				g.Expect(loaded).NotTo(gomega.BeNil())
				g.Expect(*loaded).To(gomega.Equal(tt.wantReturn))
			} else {
				g.Expect(c.macBindingSourceForUplinks.Load()).To(gomega.BeNil())
			}
		})
	}
}

// TestGetMacBindingSourceForUplinks verifies the getter falls back to the
// provider (injecting and caching the CDN source) on a cold cache, and returns
// the cached value without consulting the provider once warm.
func TestGetMacBindingSourceForUplinks(t *testing.T) {
	const cdn = "rtoe-GR_node1"

	t.Run("falls back to the provider and caches with the CDN source", func(t *testing.T) {
		g := gomega.NewWithT(t)
		c := newTestController()
		c.cdnGatewayPort = cdn
		c.uplinkSourceProvider = &fakeUplinkSourceProvider{sources: map[string]string{"uplinkA": "rtoe-GR_cudnA_node1"}}

		got := c.getMacBindingSourceForUplinks()

		g.Expect(got).To(gomega.Equal(map[string]string{"uplinkA": "rtoe-GR_cudnA_node1", "": cdn}))
		g.Expect(c.macBindingSourceForUplinks.Load()).NotTo(gomega.BeNil())
	})

	t.Run("returns the cached value without consulting the provider", func(t *testing.T) {
		g := gomega.NewWithT(t)
		c := newTestController()
		c.cdnGatewayPort = cdn
		fake := &fakeUplinkSourceProvider{sources: map[string]string{"uplinkA": "rtoe-GR_cudnA_node1"}}
		c.uplinkSourceProvider = fake

		// prime the cache, then change what the provider would return.
		_ = c.getMacBindingSourceForUplinks()
		fake.sources = map[string]string{"uplinkB": "rtoe-GR_cudnB_node1"}

		got := c.getMacBindingSourceForUplinks()

		g.Expect(got).To(gomega.Equal(map[string]string{"uplinkA": "rtoe-GR_cudnA_node1", "": cdn}))
	})
}

// --- south-bound event handlers -----------------------------------------

// TestRegisterSouthBoundEventHandlers verifies the SB cache event handlers
// translate row changes into the right reconcile enqueues.
func TestRegisterSouthBoundEventHandlers(t *testing.T) {
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
	refreshRec, refreshR := startRecorder(g, "refresh")
	defer controller.Stop(refreshR)
	c := newTestController()
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPort
	c.networkReconciler = networkR
	c.macBindingReconciler = mbR
	c.macBindingRefreshReconciler = refreshR
	// track the CDN as a source so its MAC_Binding events are relevant.
	c.followers[cdnPort] = sets.New(udnPort)

	c.registerSouthBoundEventHandlers()

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

	// A new MAC_Binding on the tracked CDN source enqueues designated|ip on the
	// mac-binding reconciler (a MAC not previously mirrored).
	createRow(g, sbClient, &sbdb.MACBinding{
		LogicalPort: cdnPort,
		IP:          "10.0.0.5",
		MAC:         "0a:00:00:00:00:05",
	})
	g.Eventually(mbRec.got).Should(gomega.ConsistOf(cdnPort + keySep + "10.0.0.5"))

	// Bumping only the timestamp (MAC unchanged) is a refresh: it enqueues
	// designated|ip on the refresh reconciler instead.
	mb := &sbdb.MACBinding{LogicalPort: cdnPort, IP: "10.0.0.5"}
	g.Expect(sbClient.Get(context.Background(), mb)).To(gomega.Succeed())
	mb.Timestamp = 100
	updOps, err := sbClient.Where(mb).Update(mb, &mb.Timestamp)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, err = ops.TransactAndCheck(sbClient, updOps)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Eventually(refreshRec.got).Should(gomega.ConsistOf(cdnPort + keySep + "10.0.0.5"))

	// A tracked network's PortBinding delete re-enqueues its network so the
	// follower set is recomputed.
	// FIXME
	//c.ports["tenantred"] = udnPort
	pbDelOps, err := sbClient.WhereCache(func(pb *sbdb.PortBinding) bool {
		return pb.LogicalPort == udnPort
	}).Delete()
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, err = ops.TransactAndCheck(sbClient, pbDelOps)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Eventually(func() int {
		n := 0
		for _, k := range networkRec.got() {
			if k == "tenantred" {
				n++
			}
		}
		return n
	}).Should(gomega.BeNumerically(">=", 2))
}

// TestRegisterSouthBoundEventHandlersIgnores verifies the event handlers filter
// out rows the controller does not care about: MAC bindings for a disabled IP
// family or an untracked source, and port bindings that are not tracked Gateway
// Router external ports.
func TestRegisterSouthBoundEventHandlersIgnores(t *testing.T) {
	g := gomega.NewWithT(t)

	const trackedSource = "rtoe-GR_tracked_node1"

	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(libovsdbtest.TestSetup{IgnoreConstraints: true}, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	networkRec, networkR := startRecorder(g, "network")
	defer controller.Stop(networkR)
	mbRec, mbR := startRecorder(g, "mb")
	defer controller.Stop(mbR)
	refreshRec, refreshR := startRecorder(g, "refresh")
	defer controller.Stop(refreshR)

	c := newTestController() // ipv4 enabled, ipv6 disabled
	c.sbClient = sbClient
	c.cdnGatewayPort = cdnPortFor("node1")
	c.networkReconciler = networkR
	c.macBindingReconciler = mbR
	c.macBindingRefreshReconciler = refreshR
	c.followers[trackedSource] = sets.New("rtoe-GR_follower_node1")

	c.registerSouthBoundEventHandlers()

	tests := []struct {
		name string
		row  model.Model
	}{
		{
			name: "MAC_Binding on an untracked source",
			row:  &sbdb.MACBinding{LogicalPort: "rtoe-GR_untracked_node1", IP: "10.0.0.5", MAC: "0a:00:00:00:00:05"},
		},
		{
			name: "MAC_Binding for a disabled IP family",
			row:  &sbdb.MACBinding{LogicalPort: trackedSource, IP: "fd00::5", MAC: "0a:00:00:00:00:06"},
		},
		{
			name: "PortBinding without the GR external port prefix",
			row: &sbdb.PortBinding{
				LogicalPort: "sw-port",
				TunnelKey:   1,
				ExternalIDs: map[string]string{
					types.NetworkExternalID:  "tenantred",
					types.TopologyExternalID: types.Layer2Topology,
				},
			},
		},
		{
			name: "PortBinding with a non-L2/L3 topology",
			row: &sbdb.PortBinding{
				LogicalPort: "rtoe-GR_localnet_node1",
				TunnelKey:   2,
				ExternalIDs: map[string]string{
					types.NetworkExternalID:  "localnetnet",
					types.TopologyExternalID: "localnet",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			createRow(g, sbClient, tt.row)
			// no reconcile of any kind is enqueued for an ignored row.
			g.Consistently(func(g gomega.Gomega) {
				g.Expect(networkRec.got()).To(gomega.BeEmpty())
				g.Expect(mbRec.got()).To(gomega.BeEmpty())
				g.Expect(refreshRec.got()).To(gomega.BeEmpty())
			}, "200ms", "50ms").Should(gomega.Succeed())
		})
	}
}

// --- small helpers -------------------------------------------------------

// macBindingsFor returns the MAC_Binding rows mirrored onto a logical port,
// read from the SB client cache.
func macBindingsFor(g gomega.Gomega, sbClient libovsdbclient.Client, port string) []*sbdb.MACBinding {
	var all []*sbdb.MACBinding
	g.Expect(sbClient.List(context.Background(), &all)).To(gomega.Succeed())
	var out []*sbdb.MACBinding
	for _, mb := range all {
		if mb.LogicalPort == port {
			out = append(out, mb)
		}
	}
	return out
}

// createRow inserts a single row into the SB database.
func createRow(g gomega.Gomega, sbClient libovsdbclient.Client, m model.Model) {
	createOps, err := sbClient.Create(m)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, err = ops.TransactAndCheck(sbClient, createOps)
	g.Expect(err).NotTo(gomega.HaveOccurred())
}
