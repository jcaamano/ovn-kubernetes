// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"strings"

	udnv1 "github.com/ovn-kubernetes/ovn-kubernetes/go-controller/pkg/crd/userdefinednetwork/v1"
)

// CompareCUDNsByAge orders ClusterUserDefinedNetworks oldest-first by their
// CreationTimestamp, breaking ties by name so the ordering is deterministic
// cluster-wide. It is suitable as a comparator for slices.SortFunc and gives a
// stable way to elect "the oldest" CUDN (e.g. the designated MAC binding mirror
// source among CUDNs sharing an uplink, or the EVPN VID conflict winner).
func CompareCUDNsByAge(a, b *udnv1.ClusterUserDefinedNetwork) int {
	if a.CreationTimestamp.Before(&b.CreationTimestamp) {
		return -1
	}
	if b.CreationTimestamp.Before(&a.CreationTimestamp) {
		return 1
	}
	return strings.Compare(a.Name, b.Name)
}
