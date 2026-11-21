// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

// ManagarmPosixModule is the coverage module of posix-subsystem.
const ManagarmPosixModule = "posix-subsystem"

type managarm struct {
	nopChecker
}

func (managarm) parseModules(files filesystem) ([]*KernelModule, error) {
	return []*KernelModule{{}, {Name: ManagarmPosixModule}}, nil
}
