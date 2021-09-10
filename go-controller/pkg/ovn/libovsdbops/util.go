package libovsdbops

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"reflect"
	"sync/atomic"

	"github.com/ovn-org/libovsdb/client"
	libovsdbmodel "github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

const (
	namedUUIDPrefix = 'u'
)

var namedUUIDCounter = rand.Uint32()

// IsNamedUUID checks if the passed id is a named-uuid built with
// BuildNamedUUID
func IsNamedUUID(id string) bool {
	return id != "" && id[0] == namedUUIDPrefix
}

// BuildNamedUUID builds an id that can be used as a named-uuid
// as per OVSDB rfc 7047 section 5.1
func BuildNamedUUID() string {
	return fmt.Sprintf("%c%010d", namedUUIDPrefix, atomic.AddUint32(&namedUUIDCounter, 1))
}

// TransactAndCheck transacts the given ops againts client and returns
// results if no error ocurred or an error otherwise.
func TransactAndCheck(client client.Client, ops []ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	if len(ops) <= 0 {
		return []ovsdb.OperationResult{{}}, nil
	}

	results, err := client.Transact(context.TODO(), ops...)
	if err != nil {
		return nil, fmt.Errorf("error in transact with ops %+v: %v", ops, err)
	}

	opErrors, err := ovsdb.CheckOperationResults(results, ops)
	if err != nil {
		return nil, fmt.Errorf("error in transact with results %+v and errors %+v: %v", results, opErrors, err)
	}

	return results, nil
}

// TransactAndCheckAndSetUUIDs transacts the given ops againts client and returns
// results if no error ocurred or an error otherwise. It sets the real uuids for
// the passed models if they were inserted and have a named-uuid (as built by
// BuildNamedUUID)
func TransactAndCheckAndSetUUIDs(client client.Client, models interface{}, ops []ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	results, err := TransactAndCheck(client, ops)
	if err != nil {
		return nil, err
	}

	s := reflect.ValueOf(models)
	if s.Kind() != reflect.Slice {
		panic("models given a non-slice type")
	}

	if s.IsNil() {
		return results, nil
	}

	namedModelMap := map[string]libovsdbmodel.Model{}
	for i := 0; i < s.Len(); i++ {
		model := s.Index(i).Interface()
		uuid := getUUID(model)
		if IsNamedUUID(uuid) {
			log.Printf("Add %s to named model map", uuid)
			namedModelMap[uuid] = model
		}
	}

	log.Printf("Considering %d ops", len(ops))
	for i, op := range ops {
		if op.Op != ovsdb.OperationInsert {
			log.Printf("Ignoring op %s", op.Op)
			continue
		}

		if !IsNamedUUID(op.UUIDName) {
			log.Printf("Ignoring non named-uuid %s", op.UUIDName)
			continue
		}

		log.Printf("Considering named-uuid %s", op.UUIDName)
		if model, ok := namedModelMap[op.UUIDName]; ok {
			log.Printf("Setting real uuid %s for named-uuid %s", results[i].UUID.GoUUID, op.UUIDName)
			setUUID(model, results[i].UUID.GoUUID)
		}
	}

	return results, nil
}

func getUUID(model libovsdbmodel.Model) string {
	switch t := model.(type) {
	case *nbdb.LoadBalancer:
		return t.UUID
	default:
		panic("Can't get UUID of an unknown libovsdb model")
	}
}

func setUUID(model libovsdbmodel.Model, uuid string) {
	switch t := model.(type) {
	case *nbdb.LoadBalancer:
		t.UUID = uuid
	default:
		panic("Can't set UUID of an unknown libovsdb model")
	}
}
