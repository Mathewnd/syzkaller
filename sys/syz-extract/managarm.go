// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/compiler"
)

// managarm consts are extracted from the headers installed into a managarm sysroot
// Values are read from the object file, since the cross-compiled binary can't run on the host.
type managarm struct{}

func (*managarm) prepare(sourcedir string, build bool, arches []*Arch) error {
	if _, err := os.Stat(filepath.Join(sourcedir, "usr", "include", "hel.h")); err != nil {
		return fmt.Errorf("-sourcedir must point to a managarm sysroot (no usr/include/hel.h): %w", err)
	}
	return nil
}

func (*managarm) prepareArch(arch *Arch) error {
	return nil
}

func (*managarm) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	args := []string{
		"-fmessage-length=0",
		"--sysroot=" + arch.sourceDir,
	}
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+filepath.Join(arch.sourceDir, incdir))
	}
	params := &extractParams{
		ExtractFromELF: true,
		TargetEndian:   arch.target.HostEndian,
	}
	return extract(info, arch.target.CCompiler, args, params)
}
