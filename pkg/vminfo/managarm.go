// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

type managarm struct {
	nopChecker
}

func (managarm) parseModules(files filesystem) ([]*KernelModule, error) {
	// thor is loaded at a fixed address and has no loadable modules.
	return []*KernelModule{{}}, nil
}
