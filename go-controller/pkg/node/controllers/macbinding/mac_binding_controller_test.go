// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package macbinding

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/client-go/util/workqueue"

	ovncnitypes "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/cni/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/config"
	controllerutil "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/controller"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/networkmanager"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
	libovsdbtest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/types"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util"
	netlinkMocks "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/util/mocks"
)

type syncOpsCall struct {
	method string
	ip     string
	mac    string
	ports  []portInfo
}

type mockSyncOps struct {
	mu        sync.Mutex
	calls     []syncOpsCall
	failFirst bool
}

func (m *mockSyncOps) getCalls() []syncOpsCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]syncOpsCall, len(m.calls))
	copy(result, m.calls)
	return result
}

func (m *mockSyncOps) clearCalls() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = nil
}

func (m *mockSyncOps) expectCalls(g gomega.Gomega, expected []syncOpsCall) {
	key := func(c syncOpsCall) string { return c.method + ":" + c.ip }
	sortCalls := func(s []syncOpsCall) {
		slices.SortFunc(s, func(a, b syncOpsCall) int { return cmp.Compare(key(a), key(b)) })
	}
	g.Eventually(func(g gomega.Gomega) {
		calls := m.getCalls()
		g.Expect(calls).To(gomega.HaveLen(len(expected)))
		sortCalls(calls)
		sortCalls(expected)
		for i, exp := range expected {
			g.Expect(calls[i].method).To(gomega.Equal(exp.method))
			g.Expect(calls[i].ip).To(gomega.Equal(exp.ip))
			g.Expect(calls[i].mac).To(gomega.Equal(exp.mac))
			if exp.ports != nil {
				g.Expect(calls[i].ports).To(gomega.ConsistOf(exp.ports))
			}
		}
	}).Should(gomega.Succeed())
	m.clearCalls()
}

func (m *mockSyncOps) expectNoCalls(g gomega.Gomega) {
	g.Consistently(func(g gomega.Gomega) {
		g.Expect(m.getCalls()).To(gomega.BeEmpty())
	}).Should(gomega.Succeed())
}

func (m *mockSyncOps) record(method, ip, mac string, ports []portInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, syncOpsCall{method: method, ip: ip, mac: mac, ports: ports})
	if m.failFirst && len(m.calls) == 1 {
		return fmt.Errorf("transient error")
	}
	return nil
}

func (m *mockSyncOps) EnsureARPFlow(ip, mac string) error {
	return m.record("EnsureARPFlow", ip, mac, nil)
}

func (m *mockSyncOps) SyncARPFlows(flows map[string]string) error {
	var err error
	for ip, mac := range flows {
		if e := m.record("SyncARPFlows", ip, mac, nil); e != nil {
			err = e
		}
	}
	return err
}

func (m *mockSyncOps) DeleteARPFlow(ip string) error {
	return m.record("DeleteARPFlow", ip, "", nil)
}

func (m *mockSyncOps) AddMACBinding(ip, mac string, timestamp int, ports []portInfo) error {
	return m.record("AddMACBinding", ip, mac, ports)
}

func (m *mockSyncOps) UpdateMACBinding(ip, mac string, timestamp int, ports []portInfo) error {
	return m.record("UpdateMACBinding", ip, mac, ports)
}

func (m *mockSyncOps) DeleteAndAddMACBinding(ip, mac string, timestamp int, ports []portInfo) error {
	return m.record("DeleteAndAddMACBinding", ip, mac, ports)
}

type testController struct {
	controller *MACBindingController
	syncOps    *mockSyncOps
	nlMock     *netlinkMocks.NetLinkOps
	neighCh    chan netlink.NeighUpdate
	stopCh     chan struct{}
}

type testControllerConfig struct {
	ipv4Enabled     bool
	ipv4UseARPFlows bool
	ipv6Enabled     bool
	ports           []portInfo
	syncOps         *mockSyncOps
	neighbors       []netlink.Neigh
	networkManager  networkmanager.Interface
	sbData          []libovsdbtest.TestData
}

func newTestController(t *testing.T, cfg testControllerConfig) *testController {
	t.Helper()
	g := gomega.NewWithT(t)

	if cfg.syncOps == nil {
		cfg.syncOps = &mockSyncOps{}
	}

	tc := &testController{
		syncOps: cfg.syncOps,
		nlMock:  &netlinkMocks.NetLinkOps{},
		neighCh: make(chan netlink.NeighUpdate, 100),
		stopCh:  make(chan struct{}),
	}

	origNlOps := util.GetNetLinkOps()
	t.Cleanup(func() {
		util.SetNetLinkOpMockInst(origNlOps)
		close(tc.stopCh)
	})
	util.SetNetLinkOpMockInst(tc.nlMock)

	bridgeLink := &netlink.Bridge{}
	bridgeLink.Index = 42
	bridgeLink.Name = "breth0"

	tc.nlMock.On("LinkByName", "breth0").Return(bridgeLink, nil)
	tc.nlMock.On("NeighList", 42, netlink.FAMILY_ALL).Return(cfg.neighbors, nil)
	tc.nlMock.On("NeighSubscribeWithOptions",
		mock.AnythingOfType("chan<- netlink.NeighUpdate"),
		mock.Anything,
		mock.Anything,
	).Run(func(args mock.Arguments) {
		ch := args.Get(0).(chan<- netlink.NeighUpdate)
		go func() {
			for update := range tc.neighCh {
				ch <- update
			}
		}()
	}).Return(nil)

	tc.controller = &MACBindingController{
		syncOps:         tc.syncOps,
		networkManager:  cfg.networkManager,
		nodeName:        "node1",
		bridgeName:      "breth0",
		ipv4Enabled:     cfg.ipv4Enabled,
		ipv4UseARPFlows: cfg.ipv4UseARPFlows,
		ipv6Enabled:     cfg.ipv6Enabled,
		cdnGatewayPort:  "rtoe-GR_node1",
	}

	if cfg.networkManager != nil {
		sbClient, sbCleanup, err := libovsdbtest.NewSBTestHarness(libovsdbtest.TestSetup{SBData: cfg.sbData}, nil)
		g.Expect(err).ToNot(gomega.HaveOccurred())
		t.Cleanup(sbCleanup.Cleanup)
		tc.controller.sbClient = sbClient
	}
	tc.controller.cache.Store(&sync.Map{})
	for _, p := range cfg.ports {
		tc.controller.ports.Store(p.LogicalPort, p)
	}
	tc.controller.bootstrapReconciler = controllerutil.NewReconciler(
		"mac-binding-bootstrap-test",
		&controllerutil.ReconcilerConfig{
			Reconcile:   tc.controller.reconcile,
			Threadiness: 1,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[string](0, 0),
		},
	)
	tc.controller.refreshReconciler = controllerutil.NewReconciler(
		"mac-binding-refresh-test",
		&controllerutil.ReconcilerConfig{
			Reconcile:   tc.controller.reconcile,
			Threadiness: 1,
			RateLimiter: workqueue.NewTypedItemExponentialFailureRateLimiter[string](0, 0),
		},
	)

	tc.controller.registerNeighEventHandler(tc.stopCh)

	err := controllerutil.Start(
		tc.controller.bootstrapReconciler,
		tc.controller.refreshReconciler,
	)
	g.Expect(err).ToNot(gomega.HaveOccurred())
	tc.controller.bootstrapReconciler.Reconcile(reconcileAll)
	g.Eventually(tc.controller.getBridgeLinkIndex).ShouldNot(gomega.Equal(0))

	return tc
}

func (tc *testController) sendNeighUpdate(ip net.IP, mac net.HardwareAddr, linkIndex int, state int, msgType uint16) {
	tc.neighCh <- netlink.NeighUpdate{
		Type: msgType,
		Neigh: netlink.Neigh{
			LinkIndex:    linkIndex,
			IP:           ip,
			HardwareAddr: mac,
			State:        state,
		},
	}
}

type neighEvent struct {
	ip        net.IP
	mac       net.HardwareAddr
	linkIndex int
	state     int
	msgType   uint16
}

type neighStep struct {
	event    neighEvent
	expected []syncOpsCall
}

func TestNeighborEvent(t *testing.T) {
	port := portInfo{LogicalPort: "rtoe-GR_blue_node1", DatapathUUID: "dp-1"}

	tests := []struct {
		name            string
		ipv4Enabled     bool
		ipv4UseARPFlows bool
		ipv6Enabled     bool
		ports           []portInfo
		syncOps         *mockSyncOps
		steps           []neighStep
	}{
		{
			name:            "IPv4 ARP flow add",
			ipv4Enabled:     true,
			ipv4UseARPFlows: true,
			ports:           []portInfo{port},
			steps: []neighStep{{
				event: neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
				expected: []syncOpsCall{
					{method: "EnsureARPFlow", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01"},
				},
			}},
		},
		{
			name:            "IPv4 ARP flow add then delete",
			ipv4Enabled:     true,
			ipv4UseARPFlows: true,
			steps: []neighStep{
				{
					event: neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
					expected: []syncOpsCall{
						{method: "EnsureARPFlow", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01"},
					},
				},
				{
					event: neighEvent{net.ParseIP("10.0.0.1"), nil, 42, netlink.NUD_FAILED, unix.RTM_DELNEIGH},
					expected: []syncOpsCall{
						{method: "DeleteARPFlow", ip: "10.0.0.1"},
					},
				},
			},
		},
		{
			name:        "IPv4 MAC binding add",
			ipv4Enabled: true,
			ports:       []portInfo{port},
			steps: []neighStep{{
				event: neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
				expected: []syncOpsCall{
					{method: "AddMACBinding", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", ports: []portInfo{port}},
				},
			}},
		},
		{
			name:        "IPv4 MAC binding add then delete",
			ipv4Enabled: true,
			ports:       []portInfo{port},
			steps: []neighStep{
				{
					event: neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
					expected: []syncOpsCall{
						{method: "AddMACBinding", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", ports: []portInfo{port}},
					},
				},
				{
					event:    neighEvent{net.ParseIP("10.0.0.1"), nil, 42, netlink.NUD_FAILED, unix.RTM_DELNEIGH},
					expected: nil,
				},
			},
		},
		{
			name:        "IPv4 MAC binding MAC change",
			ipv4Enabled: true,
			ports:       []portInfo{port},
			steps: []neighStep{
				{
					event: neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
					expected: []syncOpsCall{
						{method: "AddMACBinding", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", ports: []portInfo{port}},
					},
				},
				{
					event: neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
					expected: []syncOpsCall{
						{method: "UpdateMACBinding", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:02", ports: []portInfo{port}},
					},
				},
			},
		},
		{
			name:            "same MAC suppressed",
			ipv4Enabled:     true,
			ipv4UseARPFlows: true,
			steps: []neighStep{
				{
					event: neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
					expected: []syncOpsCall{
						{method: "EnsureARPFlow", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01"},
					},
				},
				{
					event:    neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
					expected: nil,
				},
			},
		},
		{
			name:        "IPv6 MAC binding",
			ipv6Enabled: true,
			ports:       []portInfo{port},
			steps: []neighStep{{
				event: neighEvent{net.ParseIP("fd00::1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
				expected: []syncOpsCall{
					{method: "AddMACBinding", ip: "fd00::1", mac: "aa:bb:cc:dd:ee:01", ports: []portInfo{port}},
				},
			}},
		},
		{
			name:        "multiple ports",
			ipv4Enabled: true,
			ports: []portInfo{
				{LogicalPort: "rtoe-GR_blue_node1", DatapathUUID: "dp-1"},
				{LogicalPort: "rtoe-GR_red_node1", DatapathUUID: "dp-2"},
			},
			steps: []neighStep{{
				event: neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
				expected: []syncOpsCall{
					{method: "AddMACBinding", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", ports: []portInfo{
						{LogicalPort: "rtoe-GR_blue_node1", DatapathUUID: "dp-1"},
						{LogicalPort: "rtoe-GR_red_node1", DatapathUUID: "dp-2"},
					}},
				},
			}},
		},
		{
			name:            "wrong link index ignored",
			ipv4Enabled:     true,
			ipv4UseARPFlows: true,
			steps: []neighStep{{
				event:    neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 99, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
				expected: nil,
			}},
		},
		{
			name:            "disabled IPv6 ignored",
			ipv4Enabled:     true,
			ipv4UseARPFlows: true,
			steps: []neighStep{{
				event:    neighEvent{net.ParseIP("fd00::1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
				expected: nil,
			}},
		},
		{
			name:        "no ports skips MAC binding",
			ipv4Enabled: true,
			steps: []neighStep{{
				event:    neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
				expected: nil,
			}},
		},
		{
			name:        "port without datapath skipped",
			ipv4Enabled: true,
			ports:       []portInfo{{LogicalPort: "rtoe-GR_blue_node1"}},
			steps: []neighStep{{
				event:    neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
				expected: nil,
			}},
		},
		{
			name:        "error recovery via DeleteAndAddMACBinding",
			ipv4Enabled: true,
			ports:       []portInfo{port},
			syncOps:     &mockSyncOps{failFirst: true},
			steps: []neighStep{{
				event: neighEvent{net.ParseIP("10.0.0.1"), net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, 42, netlink.NUD_REACHABLE, unix.RTM_NEWNEIGH},
				expected: []syncOpsCall{
					{method: "AddMACBinding", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", ports: []portInfo{port}},
					{method: "DeleteAndAddMACBinding", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", ports: []portInfo{port}},
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			tc := newTestController(t, testControllerConfig{
				ipv4Enabled:     tt.ipv4Enabled,
				ipv4UseARPFlows: tt.ipv4UseARPFlows,
				ipv6Enabled:     tt.ipv6Enabled,
				ports:           tt.ports,
				syncOps:         tt.syncOps,
			})

			for _, step := range tt.steps {
				e := step.event
				tc.sendNeighUpdate(e.ip, e.mac, e.linkIndex, e.state, e.msgType)

				if len(step.expected) > 0 {
					tc.syncOps.expectCalls(g, step.expected)
				} else {
					tc.syncOps.expectNoCalls(g)
				}
			}
		})
	}
}

func TestNeighborSyncOnStartup(t *testing.T) {
	port := portInfo{LogicalPort: "rtoe-GR_blue_node1", DatapathUUID: "dp-1"}

	tests := []struct {
		name            string
		ipv4UseARPFlows bool
		ports           []portInfo
		neighbors       []netlink.Neigh
		expected        []syncOpsCall
	}{
		{
			name:            "ARP flows",
			ipv4UseARPFlows: true,
			neighbors: []netlink.Neigh{
				{
					LinkIndex: 42, IP: net.ParseIP("10.0.0.1"),
					HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
					State:        netlink.NUD_REACHABLE,
				},
				{
					LinkIndex: 42, IP: net.ParseIP("10.0.0.2"),
					HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02},
					State:        netlink.NUD_REACHABLE,
				},
				{
					LinkIndex: 42, IP: net.ParseIP("10.0.0.3"),
					HardwareAddr: net.HardwareAddr{},
					State:        netlink.NUD_FAILED,
				},
			},
			expected: []syncOpsCall{
				{method: "SyncARPFlows", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01"},
				{method: "SyncARPFlows", ip: "10.0.0.2", mac: "aa:bb:cc:dd:ee:02"},
			},
		},
		{
			name:  "MAC binding recovery",
			ports: []portInfo{port},
			neighbors: []netlink.Neigh{
				{
					LinkIndex: 42, IP: net.ParseIP("10.0.0.1"),
					HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01},
					State:        netlink.NUD_REACHABLE,
				},
			},
			expected: []syncOpsCall{
				{method: "DeleteAndAddMACBinding", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", ports: []portInfo{port}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			tc := newTestController(t, testControllerConfig{
				ipv4Enabled:     true,
				ipv4UseARPFlows: tt.ipv4UseARPFlows,
				ports:           tt.ports,
				neighbors:       tt.neighbors,
			})

			tc.syncOps.expectCalls(g, tt.expected)
		})
	}
}

func TestHandleLinkEvent(t *testing.T) {
	port := portInfo{LogicalPort: "rtoe-GR_blue_node1", DatapathUUID: "dp-1"}
	g := gomega.NewWithT(t)

	tc := newTestController(t, testControllerConfig{
		ipv4Enabled:     true,
		ipv4UseARPFlows: true,
		ports:           []portInfo{port},
	})

	// Simulate a bridge recreate: new link index, new neighbors.
	newBridge := &netlink.Bridge{}
	newBridge.Index = 99
	newBridge.Name = "breth0"

	tc.nlMock.On("LinkByName", "breth0").Unset()
	tc.nlMock.On("LinkByName", "breth0").Return(newBridge, nil)
	tc.nlMock.On("NeighList", 99, netlink.FAMILY_ALL).Return([]netlink.Neigh{
		{
			LinkIndex:    99,
			IP:           net.ParseIP("10.0.0.5"),
			HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x05},
			State:        netlink.NUD_REACHABLE,
		},
	}, nil)

	tc.controller.HandleLinkEvent(newBridge)

	tc.syncOps.expectCalls(g, []syncOpsCall{
		{method: "SyncARPFlows", ip: "10.0.0.5", mac: "aa:bb:cc:dd:ee:05"},
	})
}

func TestScan(t *testing.T) {
	port := portInfo{LogicalPort: "rtoe-GR_blue_node1", DatapathUUID: "dp-1"}

	type cacheEntrySpec struct {
		ip, mac         string
		syncedTimestamp int
	}

	tests := []struct {
		name     string
		entries  []cacheEntrySpec
		expected []syncOpsCall
	}{
		{
			name: "stale entry refreshed",
			entries: []cacheEntrySpec{
				{ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", syncedTimestamp: 1},
			},
			expected: []syncOpsCall{
				{method: "UpdateMACBinding", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", ports: []portInfo{port}},
			},
		},
		{
			name: "fresh entry skipped",
			entries: []cacheEntrySpec{
				{ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", syncedTimestamp: int(time.Now().Unix())},
			},
			expected: nil,
		},
		{
			name: "mixed stale and fresh",
			entries: []cacheEntrySpec{
				{ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", syncedTimestamp: 1},
				{ip: "10.0.0.2", mac: "aa:bb:cc:dd:ee:02", syncedTimestamp: int(time.Now().Unix())},
			},
			expected: []syncOpsCall{
				{method: "UpdateMACBinding", ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01", ports: []portInfo{port}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			tc := newTestController(t, testControllerConfig{
				ipv4Enabled: true,
				ports:       []portInfo{port},
			})

			for _, e := range tt.entries {
				mac := e.mac
				entry := &macBindingCacheEntry{
					cacheEntry: cacheEntry{ip: e.ip},
				}
				entry.setMAC(&mac)
				entry.completeSync(e.syncedTimestamp)
				tc.controller.getCache().Store(e.ip, entry)
			}

			tc.controller.scan()

			if len(tt.expected) > 0 {
				tc.syncOps.expectCalls(g, tt.expected)
			} else {
				tc.syncOps.expectNoCalls(g)
			}
		})
	}
}

func newNetInfo(t *testing.T, name, topology, role string) util.NetInfo {
	t.Helper()
	netInfo, err := util.NewNetInfo(&ovncnitypes.NetConf{
		Topology: topology,
		NetConf:  cnitypes.NetConf{Name: name, Type: "ovn-k8s-cni-overlay"},
		Role:     role,
		NADName:  "ns/" + name,
	})
	gomega.NewWithT(t).Expect(err).ToNot(gomega.HaveOccurred())
	return netInfo
}

func TestReconcileNAD(t *testing.T) {
	tests := []struct {
		name              string
		nadNetworks       map[string]util.NetInfo
		nodeHasNetwork    bool
		sbData            []libovsdbtest.TestData
		existingPorts     []portInfo
		expectPorts       []portInfo
		expectHasDatapath bool
	}{
		{
			name: "add primary L3 network",
			nadNetworks: map[string]util.NetInfo{
				"ns/blue": newNetInfo(t, "blue", types.Layer3Topology, types.NetworkRolePrimary),
			},
			nodeHasNetwork: true,
			expectPorts:    []portInfo{{LogicalPort: "rtoe-GR_blue_node1", Network: "blue"}},
		},
		{
			name: "add primary L2 network",
			nadNetworks: map[string]util.NetInfo{
				"ns/blue": newNetInfo(t, "blue", types.Layer2Topology, types.NetworkRolePrimary),
			},
			nodeHasNetwork: true,
			expectPorts:    []portInfo{{LogicalPort: "rtoe-GR_blue_node1", Network: "blue"}},
		},
		{
			name: "add network picks up datapath from port binding",
			nadNetworks: map[string]util.NetInfo{
				"ns/blue": newNetInfo(t, "blue", types.Layer3Topology, types.NetworkRolePrimary),
			},
			nodeHasNetwork: true,
			sbData: []libovsdbtest.TestData{
				&sbdb.DatapathBinding{UUID: "dp-1", TunnelKey: 1},
				&sbdb.PortBinding{LogicalPort: "rtoe-GR_blue_node1", Datapath: "dp-1"},
			},
			expectPorts:       []portInfo{{LogicalPort: "rtoe-GR_blue_node1", Network: "blue"}},
			expectHasDatapath: true,
		},
		{
			name: "secondary network ignored",
			nadNetworks: map[string]util.NetInfo{
				"ns/blue": newNetInfo(t, "blue", types.Layer3Topology, types.NetworkRoleSecondary),
			},
			nodeHasNetwork: true,
		},
		{
			name: "node does not have network",
			nadNetworks: map[string]util.NetInfo{
				"ns/blue": newNetInfo(t, "blue", types.Layer3Topology, types.NetworkRolePrimary),
			},
			nodeHasNetwork: false,
		},
		{
			name: "node loses network removes port",
			nadNetworks: map[string]util.NetInfo{
				"ns/blue": newNetInfo(t, "blue", types.Layer3Topology, types.NetworkRolePrimary),
			},
			nodeHasNetwork: false,
			existingPorts:  []portInfo{{LogicalPort: "rtoe-GR_blue_node1", Network: "blue", DatapathUUID: "dp-1"}},
		},
		{
			name: "deleted network removes port",
			nadNetworks: map[string]util.NetInfo{
				"ns/blue": nil,
			},
			existingPorts: []portInfo{{LogicalPort: "rtoe-GR_blue_node1", Network: "blue", DatapathUUID: "dp-1"}},
		},
		{
			name: "deleted network leaves unrelated ports",
			nadNetworks: map[string]util.NetInfo{
				"ns/blue": nil,
				"ns/red":  newNetInfo(t, "red", types.Layer3Topology, types.NetworkRolePrimary),
			},
			nodeHasNetwork: true,
			existingPorts: []portInfo{
				{LogicalPort: "rtoe-GR_blue_node1", Network: "blue", DatapathUUID: "dp-1"},
				{LogicalPort: "rtoe-GR_red_node1", Network: "red", DatapathUUID: "dp-2"},
			},
			expectPorts: []portInfo{{LogicalPort: "rtoe-GR_red_node1", Network: "red", DatapathUUID: "dp-2"}},
		},
		{
			name: "already tracked port is not re-added",
			nadNetworks: map[string]util.NetInfo{
				"ns/blue": newNetInfo(t, "blue", types.Layer3Topology, types.NetworkRolePrimary),
			},
			nodeHasNetwork: true,
			existingPorts:  []portInfo{{LogicalPort: "rtoe-GR_blue_node1", Network: "blue", DatapathUUID: "dp-1"}},
			expectPorts:    []portInfo{{LogicalPort: "rtoe-GR_blue_node1", Network: "blue", DatapathUUID: "dp-1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)

			saved := config.OVNKubernetesFeature.EnableDynamicUDNAllocation
			config.OVNKubernetesFeature.EnableDynamicUDNAllocation = true
			t.Cleanup(func() { config.OVNKubernetesFeature.EnableDynamicUDNAllocation = saved })

			fnm := &networkmanager.FakeNetworkManager{
				NADNetworks: map[string]util.NetInfo{},
			}
			if tt.nodeHasNetwork {
				fnm.ActiveNodes = map[string]map[string]bool{}
			}
			for k, ni := range tt.nadNetworks {
				if ni != nil {
					fnm.NADNetworks[k] = ni
					if tt.nodeHasNetwork {
						fnm.ActiveNodes[ni.GetNetworkName()] = map[string]bool{"node1": true}
					}
				}
			}

			tc := newTestController(t, testControllerConfig{
				ipv4Enabled:    true,
				networkManager: fnm,
				sbData:         tt.sbData,
				ports:          tt.existingPorts,
			})

			for nadKey := range tt.nadNetworks {
				err := tc.controller.reconcileNAD(nadKey)
				g.Expect(err).ToNot(gomega.HaveOccurred())
			}

			var gotPorts []portInfo
			tc.controller.ports.Range(func(_, value any) bool {
				gotPorts = append(gotPorts, value.(portInfo))
				return true
			})

			if len(tt.expectPorts) == 0 {
				g.Expect(gotPorts).To(gomega.BeEmpty())
			} else if tt.expectHasDatapath {
				g.Expect(gotPorts).To(gomega.HaveLen(len(tt.expectPorts)))
				for i, exp := range tt.expectPorts {
					g.Expect(gotPorts[i].LogicalPort).To(gomega.Equal(exp.LogicalPort))
					g.Expect(gotPorts[i].Network).To(gomega.Equal(exp.Network))
					g.Expect(gotPorts[i].DatapathUUID).ToNot(gomega.BeEmpty())
				}
			} else {
				g.Expect(gotPorts).To(gomega.ConsistOf(tt.expectPorts))
			}
		})
	}
}
