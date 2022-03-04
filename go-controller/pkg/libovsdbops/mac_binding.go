package libovsdbops

import (
	libovsdbclient "github.com/ovn-org/libovsdb/client"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
)

// CreateOrUpdateMacBinding creates or updates the provided mac binding
func CreateOrUpdateMacBinding(sbClient libovsdbclient.Client, mb *sbdb.MACBinding) error {
	opModel := OperationModel{
		Model:          mb,
		OnModelUpdates: []interface{}{},
		ErrNotFound:    false,
		BulkOp:         false,
	}

	m := NewModelClient(sbClient)
	_, err := m.CreateOrUpdate(opModel)
	return err
}

type macBindingPredicate func(*sbdb.MACBinding) bool

// DeleteMacBindingWithPredicate looks up mac bindings from the cache based on a
// given predicate and deletes them
func DeleteMacBindingWithPredicate(sbClient libovsdbclient.Client, p macBindingPredicate) error {
	deleted := []*sbdb.MACBinding{}
	opModel := OperationModel{
		ModelPredicate: p,
		ExistingResult: &deleted,
		ErrNotFound:    false,
		BulkOp:         true,
	}

	m := NewModelClient(sbClient)
	return m.Delete(opModel)
}
