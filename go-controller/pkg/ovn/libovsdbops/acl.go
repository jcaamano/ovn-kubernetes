package libovsdbops

import (
	"fmt"
	"reflect"

	libovsdbclient "github.com/ovn-org/libovsdb/client"
	libovsdb "github.com/ovn-org/libovsdb/ovsdb"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

// isEquivalentACL if it hase same uuid, or if it has same name
// and external ids, or if it has same priority, direction, match
// and action.
func isEquivalentACL(existing *nbdb.ACL, new *nbdb.ACL) bool {
	if existing.UUID != "" && existing.UUID == new.UUID {
		return true
	}
	// TODO if we want to support adding/removing external ids,
	// we need to compare them differently
	if len(existing.Name) > 0 && reflect.DeepEqual(existing.Name, new.Name) && reflect.DeepEqual(existing.ExternalIDs, new.ExternalIDs) {
		return true
	}

	return existing.Priority == new.Priority &&
		existing.Direction == new.Direction &&
		existing.Match == new.Match &&
		existing.Action == new.Action
}

// findACL looks up the client cache for ACLs that that are equivalent
func findACL(nbClient libovsdbclient.Client, acl *nbdb.ACL) (string, error) {
	acls := []nbdb.ACL{}
	err := nbClient.WhereCache(func(item *nbdb.ACL) bool {
		return isEquivalentACL(item, acl)
	}).List(&acls)
	if err != nil {
		return "", fmt.Errorf("error finding ACL: %v", err)
	}

	if len(acls) > 1 {
		return "", fmt.Errorf("unexpectedly found multiple equivalent ACLs: %+v", acls)
	}

	if len(acls) == 1 {
		return acls[0].UUID, nil
	}

	return "", nil
}

func BuildACL(name, direction, match, action, meter, severity string, priority int, log bool, externalIds map[string]string) *nbdb.ACL {
	uuid := buildNamedUUID(fmt.Sprintf("acl_%s_%d_%s_%s", direction, priority, match, action))
	var nameSet []string
	if name != "" {
		nameSet = []string{name}
	}
	return &nbdb.ACL{
		UUID:        uuid,
		Name:        nameSet,
		Direction:   direction,
		Match:       match,
		Action:      action,
		Priority:    priority,
		Severity:    []string{severity},
		Log:         log,
		Meter:       []string{meter},
		ExternalIDs: externalIds,
	}
}

func CreateOrUpdateACLOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, acl *nbdb.ACL) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findACL(nbClient, acl)
	if err != nil {
		return nil, err
	}

	// If ACL already exists, update it
	if uuid != "" {
		acl.UUID = uuid
		op, err := nbClient.Where(acl).Update(acl)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op...)
		return ops, nil
	}

	op, err := nbClient.Create(acl)
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}

func CreateOrUpdateACL(nbClient libovsdbclient.Client, acl *nbdb.ACL) error {
	ops, err := CreateOrUpdateACLOps(nbClient, nil, acl)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}

func UpdateACLOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, acl *nbdb.ACL) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findACL(nbClient, acl)
	if err != nil {
		return nil, err
	}

	if uuid == "" {
		return nil, fmt.Errorf("error, acl not found %+v", acl)
	}

	acl.UUID = uuid
	op, err := nbClient.Where(acl).Update(acl)
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}

func UpdateACL(nbClient libovsdbclient.Client, acl *nbdb.ACL) error {
	ops, err := UpdateACLOps(nbClient, nil, acl)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}

func UpdateACLLoggingOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, acl *nbdb.ACL) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}

	uuid, err := findACL(nbClient, acl)
	if err != nil {
		return nil, err
	}

	if uuid == "" {
		return nil, fmt.Errorf("error, acl not found %+v", acl)
	}

	acl.UUID = uuid
	op, err := nbClient.Where(acl).Update(acl, &acl.Severity, &acl.Log)
	if err != nil {
		return nil, err
	}
	ops = append(ops, op...)

	return ops, nil
}

func UpdateACLLogging(nbClient libovsdbclient.Client, acl *nbdb.ACL) error {
	ops, err := UpdateACLLoggingOps(nbClient, nil, acl)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}

func CreateOrUpdateACLsOps(nbClient libovsdbclient.Client, ops []libovsdb.Operation, acls ...*nbdb.ACL) ([]libovsdb.Operation, error) {
	if ops == nil {
		ops = []libovsdb.Operation{}
	}
	for _, acl := range acls {
		var err error
		ops, err = CreateOrUpdateACLOps(nbClient, ops, acl)
		if err != nil {
			return nil, err
		}
	}

	return ops, nil
}

func CreateOrUpdateACLs(nbClient libovsdbclient.Client, acls []*nbdb.ACL) error {
	ops, err := CreateOrUpdateACLsOps(nbClient, nil, acls...)
	if err != nil {
		return err
	}

	_, err = TransactAndCheck(nbClient, ops)
	return err
}
