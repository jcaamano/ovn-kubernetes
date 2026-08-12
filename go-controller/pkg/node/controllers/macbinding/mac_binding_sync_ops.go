// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package macbinding

import libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"

// newMACBindingSyncOps creates the macBindingSyncOps implementation.
func newMACBindingSyncOps(_ libovsdbclient.Client, _ openFlowManager) macBindingSyncOps {
	// TODO: return concrete implementation
	return nil
}
