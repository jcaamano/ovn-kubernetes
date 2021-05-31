package addressset

import "k8s.io/klog/v2"

// NonDualStackAddressSetCleanup cleans addresses in old non dual stack format.
// This method should only be called after ensuring address sets in old format
// are no longer being referenced.
func NonDualStackAddressSetCleanup() error {
	// For each address set, track if it is in old non dual stack
	// format and in new dual stack format
	addressSets := map[string][2]bool{}
	err := forEachAddressSet(func(name string) {
		shortName := truncateSuffixFromAddressSet(name)
		info, found := addressSets[shortName]
		if !found {
			info = [2]bool{false, false}
		}
		if shortName == name {
			// This address set is in old non dual stack format
			klog.Infof("address set is in old format: %s", name)
			info[0] = true
		} else {
			// This address set is in new dual stack format
			klog.Infof("address set is in new format: %s", name)
			info[1] = true
		}
		addressSets[shortName] = info
	})
	if err != nil {
		return err
	}

	for name, info := range addressSets {
		// If we have an address set in both old and new formats,
		// we can safely remove the old format.
		if info[0] && info[1] {
			klog.Infof("address set is in both formats, destroy: %s", name)
			err := destroyAddressSet(name)
			if err != nil {
				return err
			}
		}
	}

	return nil
}