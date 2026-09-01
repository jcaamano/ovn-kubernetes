// SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
// SPDX-License-Identifier: Apache-2.0

package testcontext

import (
	"errors"
	"sync"

	"github.com/onsi/ginkgo/v2"
	"k8s.io/kubernetes/test/e2e/framework"
)

type TestContext struct {
	sync.Mutex
	cleanUpFns []func() error
}

func (c *TestContext) AddCleanUpFn(cleanUpFn func() error) {
	c.Lock()
	defer c.Unlock()
	c.addCleanUpFn(cleanUpFn)
}

func (c *TestContext) addCleanUpFn(cleanUpFn func() error) {
	c.cleanUpFns = append(c.cleanUpFns, cleanUpFn)
}

func (c *TestContext) CleanUp() error {
	c.Lock()
	defer c.Unlock()
	if !framework.TestContext.DeleteNamespace {
		return nil
	}
	if !framework.TestContext.DeleteNamespaceOnFailure && ginkgo.CurrentSpecReport().Failed() {
		return nil
	}
	err := c.cleanUp()
	if err != nil {
		framework.Logf("Cleanup failed: %v", err)
	}
	return err
}

// CleanUp must be synchronized by caller
func (c *TestContext) cleanUp() error {
	var errs []error
	// generic cleanup activities
	for i := len(c.cleanUpFns) - 1; i >= 0; i-- {
		if err := c.cleanUpFns[i](); err != nil {
			errs = append(errs, err)
		}
	}
	c.cleanUpFns = nil
	return errors.Join(errs...)
}
