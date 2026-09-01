// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package macbinding

import (
	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
)

// portInfo identifies a target Gateway Router external port and its datapath.
// It is a transient value built at write time; the datapath is resolved lazily
// and never cached on the controller.
type portInfo struct {
	LogicalPort  string
	DatapathUUID string
}

// macBindingSyncOps abstracts the SB MAC_Binding writes used to mirror a
// designated Gateway Router's binding onto target Gateway Routers.
type macBindingSyncOps interface {
	// SetMACBindings writes (ip, mac) as a MAC_Binding row for each target
	// port in a single transaction, replacing any existing row for the same
	// (logical_port, ip). The caller passes a fresh timestamp (time.Now) so
	// mirrored entries never move a target's timestamp backwards.
	SetMACBindings(macBindings map[string]string, timestamp int, ports []portInfo) error
}

type macSyncer struct {
	sbClient libovsdbclient.Client
}

func newMACBindingSyncOps(sbClient libovsdbclient.Client) macBindingSyncOps {
	return &macSyncer{sbClient: sbClient}
}

// SetMACBindings removes the MAC_Binding for each port and re-creates it in a
// single transaction, so the write is idempotent regardless of whether a row
// already exists for the (logical_port, ip) pair.
func (b *macSyncer) SetMACBindings(macBindings map[string]string, timestamp int, ports []portInfo) error {
	allOps := make([]ovsdb.Operation, 0, 2*len(ports))
	for _, port := range ports {
		for ip, mac := range macBindings {
			deleteOps, err := b.sbClient.Where(&sbdb.MACBinding{
				LogicalPort: port.LogicalPort,
				IP:          ip,
			}).Delete()
			if err != nil {
				return err
			}
			allOps = append(allOps, deleteOps...)

			createOps, err := b.sbClient.Create(&sbdb.MACBinding{
				IP:          ip,
				MAC:         mac,
				LogicalPort: port.LogicalPort,
				Datapath:    port.DatapathUUID,
				Timestamp:   timestamp,
			})
			if err != nil {
				return err
			}
			allOps = append(allOps, createOps...)
		}
	}
	_, err := ops.TransactAndCheck(b.sbClient, allOps)
	return err
}
