package libovsdbops

import (
	libovsdbclient "github.com/ovn-org/libovsdb/client"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

// GetNBGlobal looks up the NB Global entry from the cache
func GetNBGlobal(nbClient libovsdbclient.Client) (*nbdb.NBGlobal, error) {
	found := []*nbdb.NBGlobal{}
	opModel := OperationModel{
		ModelPredicate: func(item *nbdb.NBGlobal) bool { return true },
		ExistingResult: &found,
		OnModelUpdates: nil, // no update
		ErrNotFound:    true,
		BulkOp:         false,
	}

	m := NewModelClient(nbClient)
	_, err := m.CreateOrUpdate(opModel)
	return found[0], err
}

// UpdateNBGlobalSetOptions sets options on the NB Global entry adding any
// missing, removing the ones set to an empty value and updating existing
func UpdateNBGlobalSetOptions(nbClient libovsdbclient.Client, nbGlobal *nbdb.NBGlobal) error {
	options := nbGlobal.Options
	// find the nbGlobal table's UUID, we don't have any other way to reliably look this table entry since it can
	// only be indexed by UUID
	nbGlobal, err := GetNBGlobal(nbClient)
	if err != nil {
		return err
	}

	if nbGlobal.Options == nil {
		nbGlobal.Options = map[string]string{}
	}

	for k, v := range options {
		if v == "" {
			delete(nbGlobal.Options, k)
		} else {
			nbGlobal.Options[k] = v
		}
	}

	// Update the options column in the nbGlobal entry since we already performed a lookup
	opModel := OperationModel{
		Model: nbGlobal,
		OnModelUpdates: []interface{}{
			&nbGlobal.Options,
		},
		ErrNotFound: true,
		BulkOp:      false,
	}

	m := NewModelClient(nbClient)
	_, err = m.CreateOrUpdate(opModel)
	return err
}
