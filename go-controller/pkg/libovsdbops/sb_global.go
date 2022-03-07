package libovsdbops

import (
	libovsdbclient "github.com/ovn-org/libovsdb/client"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
)

// GetNBGlobal looks up the SB Global entry from the cache
func GetSBGlobal(sbClient libovsdbclient.Client) (*sbdb.SBGlobal, error) {
	found := []*sbdb.SBGlobal{}
	opModel := operationModel{
		ModelPredicate: func(item *sbdb.SBGlobal) bool { return true },
		ExistingResult: &found,
		OnModelUpdates: nil, // no update
		ErrNotFound:    true,
		BulkOp:         false,
	}

	m := newModelClient(sbClient)
	_, err := m.CreateOrUpdate(opModel)
	return found[0], err
}
