// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package libovsdb

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

	"github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/sbdb"
)

var (
	datapathMonitorMu        sync.Mutex
	datapathMonitoredClients = map[libovsdbclient.Client]struct{}{}
)

// MonitorDatapathBindings establishes a monitor on the SB DatapathBinding table
// for the given test client. Production SB clients do not monitor
// DatapathBinding (its rows are handled via the native/direct API), so the test
// harness does not monitor it either; tests that need those rows in the client
// cache must opt in by calling this helper. It is safe to call more than once
// per client.
func MonitorDatapathBindings(sbClient libovsdbclient.Client) error {
	datapathMonitorMu.Lock()
	defer datapathMonitorMu.Unlock()
	if _, ok := datapathMonitoredClients[sbClient]; ok {
		return nil
	}
	_, err := sbClient.Monitor(context.Background(), sbClient.NewMonitor(libovsdbclient.WithTable(&sbdb.DatapathBinding{})))
	if err != nil {
		return err
	}
	datapathMonitoredClients[sbClient] = struct{}{}
	return nil
}

func CreateTransitSwitchPortBindings(sbClient libovsdbclient.Client, datapath string, names ...string) error {
	// CreateTransitSwitchPortBindings dedups datapaths via a cache Get, so it
	// needs the DatapathBinding table monitored.
	if err := MonitorDatapathBindings(sbClient); err != nil {
		return err
	}

	h := fnv.New32a()
	h.Write([]byte(datapath))
	dp := &sbdb.DatapathBinding{
		TunnelKey: int(h.Sum32()),
	}

	err := sbClient.Get(context.Background(), dp)
	datapathUUID := dp.UUID
	if errors.Is(err, libovsdbclient.ErrNotFound) {
		ops, err := sbClient.Create(dp)
		if err != nil {
			return err
		}
		r, err := sbClient.Transact(context.Background(), ops...)
		if err != nil {
			return err
		}
		if len(r) != 1 {
			return fmt.Errorf("expected single result when creating datapath binding but got %v", r)
		}
		datapathUUID = r[0].UUID.GoUUID
	}

	for _, name := range names {
		h := fnv.New32a()
		h.Write([]byte(name))
		pb := &sbdb.PortBinding{
			LogicalPort: name,
			Datapath:    datapathUUID,
			TunnelKey:   int(h.Sum32()),
		}

		ops, err := sbClient.Create(pb)
		if err != nil {
			return err
		}
		_, err = sbClient.Transact(context.Background(), ops...)
		if err != nil {
			return err
		}
	}

	return nil
}
