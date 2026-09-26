// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

type astral struct {
	nopChecker
}

func (astral) parseModules(files filesystem) ([]*KernelModule, error) {
	// Astral has a fixed-address kernel and no loadable modules. The unnamed
	// entry lets FixModules attach the kernel ELF's path and size for coverage.
	return []*KernelModule{{}}, nil
}
