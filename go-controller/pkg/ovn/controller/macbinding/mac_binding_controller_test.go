// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package macbinding

import (
	"context"
	"sync"
	"testing"

	"github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/util/sets"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
	libovsdbtest "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/testing/libovsdb"
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

func (m *mockSyncOps) SetMACBindings(ip, mac string, timestamp int, ports []portInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, syncCall{ip: ip, mac: mac, timestamp: timestamp, ports: ports})
	return nil
}

func (m *mockSyncOps) getCalls() []syncCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]syncCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// newTestController builds a controller wired only with the fields the
// method-level tests exercise, bypassing NewMACBindingController (which needs a
// live networkManager and watchFactory).
func newTestController(syncOps macBindingSyncOps) *MACBindingController {
	return &MACBindingController{
		syncOps:          syncOps,
		nodeName:         "node1",
		ipv4Enabled:      true,
		followers:        map[string]sets.Set[string]{},
		ports:            map[string]string{},
		monitorCookies:   map[string]libovsdbclient.MonitorCookie{},
	}
}

func TestParseKey(t *testing.T) {
	g := gomega.NewWithT(t)
	dp, ip := parseKey("gr-port|10.0.0.5")
	g.Expect(dp).To(gomega.Equal("gr-port"))
	g.Expect(ip).To(gomega.Equal("10.0.0.5"))

	dp, ip = parseKey("gr-port")
	g.Expect(dp).To(gomega.Equal("gr-port"))
	g.Expect(ip).To(gomega.BeEmpty())
}

func TestIPEnabled(t *testing.T) {
	g := gomega.NewWithT(t)
	c := &MACBindingController{ipv4Enabled: true, ipv6Enabled: false}
	g.Expect(c.ipEnabled("10.0.0.5")).To(gomega.BeTrue())
	g.Expect(c.ipEnabled("fd00::5")).To(gomega.BeFalse())

	c = &MACBindingController{ipv4Enabled: false, ipv6Enabled: true}
	g.Expect(c.ipEnabled("10.0.0.5")).To(gomega.BeFalse())
	g.Expect(c.ipEnabled("fd00::5")).To(gomega.BeTrue())
}

// TestReconcileOne verifies the mirror read path: given a designated source
// MAC_Binding and a target Gateway Router port, reconcileOne resolves the
// target datapath and mirrors the (ip, mac) pair onto it.
func TestReconcileOne(t *testing.T) {
	g := gomega.NewWithT(t)

	const (
		cdnPort    = "cdn-gr-port"
		targetPort = "udn-gr-port"
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

	tgtPB, err := ops.GetPortBinding(sbClient, &sbdb.PortBinding{LogicalPort: targetPort})
	g.Expect(err).NotTo(gomega.HaveOccurred())

	g.Expect(c.reconcileOne(cdnPort, srcIP)).To(gomega.Succeed())

	calls := mock.getCalls()
	g.Expect(calls).To(gomega.HaveLen(1))
	g.Expect(calls[0].ip).To(gomega.Equal(srcIP))
	g.Expect(calls[0].mac).To(gomega.Equal(srcMAC))
	g.Expect(calls[0].ports).To(gomega.ConsistOf(portInfo{LogicalPort: targetPort, DatapathUUID: tgtPB.Datapath}))
}

// TestReconcileOneNoSource confirms a missing source binding is a no-op: targets
// are left to age out rather than being cleared.
func TestReconcileOneNoSource(t *testing.T) {
	g := gomega.NewWithT(t)

	const cdnPort = "cdn-gr-port"

	setup := libovsdbtest.TestSetup{
		IgnoreConstraints: true,
		SBData: []libovsdbtest.TestData{
			&sbdb.DatapathBinding{UUID: "tgt-dp"},
			&sbdb.PortBinding{UUID: "tgt-pb", LogicalPort: "udn-gr-port", Datapath: "tgt-dp"},
		},
	}
	sbClient, cleanup, err := libovsdbtest.NewSBTestHarness(setup, nil)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	defer cleanup.Cleanup()

	mock := &mockSyncOps{}
	c := newTestController(mock)
	c.sbClient = sbClient
	c.followers[cdnPort] = sets.New("udn-gr-port")

	g.Expect(c.reconcileOne(cdnPort, "10.0.0.9")).To(gomega.Succeed())
	g.Expect(mock.getCalls()).To(gomega.BeEmpty())
}

// TestSetMACBindings verifies the actual SB write path: SetMACBindings creates
// (and replaces) a MAC_Binding row for each target port.
func TestSetMACBindings(t *testing.T) {
	g := gomega.NewWithT(t)

	const (
		targetPort = "udn-gr-port"
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

	// Resolve the real datapath UUID assigned by the server.
	var dps []*sbdb.DatapathBinding
	g.Expect(sbClient.List(context.Background(), &dps)).To(gomega.Succeed())
	g.Expect(dps).To(gomega.HaveLen(1))
	dpUUID := dps[0].UUID

	syncOps := newMACBindingSyncOps(sbClient)
	g.Expect(syncOps.SetMACBindings(ip, mac, 200, []portInfo{{LogicalPort: targetPort, DatapathUUID: dpUUID}})).To(gomega.Succeed())

	g.Eventually(sbClient).Should(libovsdbtest.HaveDataSubset(
		&sbdb.MACBinding{LogicalPort: targetPort, IP: ip, MAC: mac, Datapath: dpUUID, Timestamp: 200},
	))

	// A second write with a newer timestamp replaces the row rather than
	// duplicating it.
	g.Expect(syncOps.SetMACBindings(ip, "0a:00:00:00:00:99", 300, []portInfo{{LogicalPort: targetPort, DatapathUUID: dpUUID}})).To(gomega.Succeed())
	g.Eventually(func(g gomega.Gomega) {
		var mbs []*sbdb.MACBinding
		g.Expect(sbClient.List(context.Background(), &mbs)).To(gomega.Succeed())
		g.Expect(mbs).To(gomega.HaveLen(1))
		g.Expect(mbs[0].MAC).To(gomega.Equal("0a:00:00:00:00:99"))
		g.Expect(mbs[0].Timestamp).To(gomega.Equal(300))
	}).Should(gomega.Succeed())
}
