// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package macbinding

import libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

// newMACBindingSyncOps creates the macBindingSyncOps implementation.
func newMACBindingSyncOps(sbClient libovsdbclient.Client, ofm openFlowManager) macBindingSyncOps {
	// TODO: return concrete implementation
	return nil
}

// macBindingSyncOps abstracts the operations used to propagate a CDN
// Gateway Router MAC_Binding entry to UDN Gateway Routers. A single
// implementation provides both ARP flow and MAC_Binding methods.
//
// The reconciler passes a fresh timestamp (time.Now) to MAC_Binding
// methods, not the CDN entry's timestamp, to avoid moving UDN
// timestamps backwards.
//
// There is no DeleteMACBinding: UDN entries age out naturally via
// OVN's mac_binding_age_threshold.
//
// The implementation must be safe for concurrent use from multiple
// reconciler workers.
type macBindingSyncOps interface {
	// EnsureARPFlow programs an OpenFlow ARP responder rule on br-ex via
	// the openflowManager for the given (IP, MAC) pair. When a UDN GR
	// sends an ARP request for this IP, br-ex replies directly with
	// the known MAC, avoiding broadcast.
	EnsureARPFlow(ip, mac string) error
	SyncARPFlows(map[string]string) error

	// DeleteARPFlow removes the ARP responder flow for the given IP.
	DeleteARPFlow(ip string) error

	// AddMACBinding inserts a MAC_Binding row in SBDB for each UDN GR
	// external port in ports. Used when syncedTimestamp == 0 (entry
	// never synced).
	AddMACBinding(ip, mac string, timestamp int, ports []portInfo) error

	// UpdateMACBinding conditionally updates existing MAC_Binding rows
	// for each UDN GR external port in ports. The OVSDB update must
	// include a timestamp < new_timestamp condition to handle the
	// residual race between computing time.Now and transaction commit:
	// the UDN GR's own statctrl may refresh the timestamp in that
	// window. A no-op update (0 rows, condition not met) is not an
	// error and must not trigger recovery.
	UpdateMACBinding(ip, mac string, timestamp int, ports []portInfo) error

	// DeleteAndAddMACBinding performs a conditional delete followed by
	// a create in a single OVSDB transaction. Used for error recovery
	// when the controller's cache has diverged from SBDB state (e.g.
	// AddMACBinding failed with duplicate, or UpdateMACBinding failed
	// with row missing). Like UpdateMACBinding, the delete must be
	// conditioned on timestamp < new_timestamp to avoid replacing an
	// entry that the UDN's own statctrl has already refreshed to a
	// newer value. A no-op (condition not met) is not an error.
	DeleteAndAddMACBinding(ip, mac string, timestamp int, ports []portInfo) error
}
