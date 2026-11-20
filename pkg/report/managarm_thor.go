// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/ianlancetaylor/demangle"
)

func (ctx *managarm) findThorCrash(output []byte) *Report {
	for start := 0; start < len(output); {
		rep := ctx.firstOops(output, start, managarmThorOopses)
		if rep == nil {
			return nil
		}

		line := managarmPlain(output[rep.StartPos:rep.EndPos])

		// frigg prints failed assertions the same in thor and mlibc, so check if this is a user crash.
		userAssertion := bytes.HasPrefix(line, []byte("Assertion failed: ")) &&
			managarmUserCrashFollows(output, rep.EndPos+1)
		if !userAssertion {
			return rep
		}

		start = rep.EndPos + 1
	}

	return nil
}


var managarmFaultIP = regexp.MustCompile(`^thor: .* in kernel, .*faulting ip: (?:0x)?([0-9a-fA-F]+)`)

// Add location information to a title.
func (ctx *managarm) symbolizeThorTitle(rep *Report,
	symbFunc func(string, ...uint64) ([]symbolizer.Frame, error)) {
	match := managarmFaultIP.FindSubmatch(managarmPlain(rep.Output[rep.StartPos:rep.EndPos]))
	if match == nil {
		return
	}

	pc, err := strconv.ParseUint(string(match[1]), 16, 64)
	if err != nil {
		return
	}

	frames, err := symbFunc(filepath.Join(ctx.kernelDirs.Obj, ctx.target.KernelObject), pc)
	if err != nil {
		return
	}

	var file, fn string
	for _, frame := range frames {
		if frame.Func == "" || frame.Func == "??" || frame.File == "" || frame.File == "??" {
			continue
		}

		path := managarmSourcePath(frame.File, ctx.kernelDirs.BuildSrc, ctx.kernelDirs.Src)
		if fn == "" || strings.HasPrefix(path, "kernel/") {
			file, fn = path, demangle.Filter(frame.Func, demangle.NoParams, demangle.NoTemplateParams)
		}

		if strings.HasPrefix(path, "kernel/") {
			break
		}
	}

	if fn == "" {
		return
	}

	rep.Title = managarmTitleAt(rep.Title, file, fn)
	rep.Type = crash.TitleToType(rep.Title)
}

var managarmTraceIP = regexp.MustCompile(`^\s*<0x([0-9a-fA-F]+)>\s*$`)

func managarmThorIP(line []byte) (match [][]byte, isFrame bool) {
	if match := managarmTraceIP.FindSubmatch(line); match != nil {
		return match, true
	}
	return managarmFaultIP.FindSubmatch(line), false
}

var managarmThorOopses = []*oops{
	{
		[]byte("thor: Page fault in kernel"),
		[]oopsFormat{
			{
				title:        compile(`thor: Page fault in kernel`),
				fmt:          "thor: page fault in kernel",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte(" fault in kernel"),
		[]oopsFormat{
			{
				title:        compile(`thor: Unhandled ([a-z-]+) fault in kernel`),
				fmt:          "thor: unhandled %[1]v fault in kernel",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("thor: Attempt to access "),
		[]oopsFormat{
			{
				title:        compile(`thor: Attempt to access ((?:unmapped )?kernel memory)`),
				fmt:          "thor: attempt to access %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("thor: SMAP fault"),
		[]oopsFormat{
			{
				title:        compile(`thor: SMAP fault`),
				fmt:          "thor: SMAP fault",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("thor: Out of "),
		[]oopsFormat{
			{
				title:        compile(`thor: (Out of [^\x1b\r\n]*)`),
				fmt:          "thor: %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("thor: Kernel heap allocation failed"),
		[]oopsFormat{
			{
				title:        compile(`thor: (Kernel heap allocation failed[^\x1b\r\n]*)`),
				fmt:          "thor: %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("thor: operator delete() called"),
		[]oopsFormat{
			{
				title:        compile(`thor: operator delete\(\) called`),
				fmt:          "thor: operator delete() called",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("Assertion failed: "),
		[]oopsFormat{
			{
				title:        compile(`Assertion failed: ([^\x1b\r\n]*)`),
				report:       compile(`Assertion failed: [^\n]*\n[^\n]*In function ([^\x1b\r\n]*) at `),
				fmt:          "thor: assertion failed in %[1]v",
				noStackTrace: true,
			},
			{
				title:        compile(`Assertion failed: ([^\x1b\r\n]*)`),
				fmt:          "thor: assertion failed: %[1]v",
				noStackTrace: true,
				corrupted:    true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("frg: Panic!"),
		[]oopsFormat{
			{
				title:        compile(`frg: Panic! ([^\x1b\r\n]*)`),
				fmt:          "frg: panic: %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("Pure virtual call"),
		[]oopsFormat{
			{
				title:        compile(`Pure virtual call`),
				fmt:          "thor: pure virtual call",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("abort() was called"),
		[]oopsFormat{
			{
				title:        compile(`abort\(\) was called`),
				fmt:          "thor: abort() was called",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
}
