// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package report

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/ianlancetaylor/demangle"
)

type managarm struct {
	*config
}

func ctorManagarm(cfg *config) (reporterImpl, []string, error) {
	return &managarm{config: cfg}, nil, nil
}

func (ctx *managarm) ContainsCrash(output []byte) bool {
	return containsCrash(output, managarmOopses, ctx.ignores)
}

func (ctx *managarm) Parse(output []byte) *Report {
	rep := simpleLineParser(output, managarmOopses, nil, ctx.ignores)
	if rep == nil {
		return nil
	}
	if ctx.kernelDirs.Obj != "" {
		symb := symbolizer.Make(ctx.target)
		defer symb.Close()
		ctx.symbolizeTitle(rep, symb.Symbolize)
	}
	return rep
}

var managarmFaultIP = regexp.MustCompile(`^thor: .*faulting ip: (?:0x)?([0-9a-fA-F]+)`)

func (ctx *managarm) symbolizeTitle(rep *Report,
	symbFunc func(string, ...uint64) ([]symbolizer.Frame, error)) {
	line := rep.Output[rep.StartPos:rep.EndPos]
	match := managarmFaultIP.FindSubmatch(managarmColor.ReplaceAll(line, nil))
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
	rep.Title = fmt.Sprintf("%v at %v in %v", rep.Title, file, fn)
	rep.Type = crash.TitleToType(rep.Title)
}

func managarmSourcePath(file string, roots ...string) string {
	for _, root := range roots {
		if root != "" {
			file = strings.TrimPrefix(file, filepath.Clean(root)+"/")
		}
	}
	for _, marker := range []string{"/src/managarm/", "/usr/share/frigg/include/", "/usr/include/"} {
		if i := strings.LastIndex(file, marker); i != -1 {
			file = file[i+len(marker):]
			break
		}
	}
	for strings.HasPrefix(file, "../") || strings.HasPrefix(file, "./") {
		file = file[strings.IndexByte(file, '/')+1:]
	}
	return file
}

var managarmTraceIP = regexp.MustCompile(`^\s*<0x([0-9a-fA-F]+)>\s*$`)

func (ctx *managarm) Symbolize(rep *Report) error {
	if ctx.kernelDirs.Obj == "" {
		return nil
	}
	symb := symbolizer.Make(ctx.target)
	defer symb.Close()
	var symbolized []byte
	for _, line := range bytes.SplitAfter(rep.Report, []byte("\n")) {
		symbolized = append(symbolized, ctx.symbolizeLine(symb.Symbolize, line)...)
	}
	rep.Report = symbolized
	return nil
}

func (ctx *managarm) symbolizeLine(symbFunc func(string, ...uint64) ([]symbolizer.Frame, error),
	line []byte) []byte {
	plain := managarmColor.ReplaceAll(bytes.TrimRight(line, "\r\n"), nil)
	match := managarmTraceIP.FindSubmatch(plain)
	isReturn := match != nil
	if match == nil {
		if match = managarmFaultIP.FindSubmatch(plain); match == nil {
			return line
		}
	}
	pc, err := strconv.ParseUint(string(match[1]), 16, 64)
	if err != nil {
		return line
	}
	lookup := pc
	if isReturn {
		lookup--
	}
	frames, err := symbFunc(filepath.Join(ctx.kernelDirs.Obj, ctx.target.KernelObject), lookup)
	if err != nil || len(frames) == 0 {
		return line
	}
	var out []byte
	if !isReturn {
		out = append(out, bytes.TrimRight(line, "\n")...)
		out = append(out, '\n')
	}
	for _, frame := range frames {
		fn := frame.Func
		if fn != "??" {
			fn = demangle.Filter(fn, demangle.NoParams, demangle.NoTemplateParams)
		}
		file := managarmSourcePath(frame.File, ctx.kernelDirs.BuildSrc, ctx.kernelDirs.Src)
		inline := ""
		if frame.Inline {
			inline = " [inline]"
		}
		out = fmt.Appendf(out, "\t<%#x> %v %v:%v%v\n", pc, fn, file, frame.Line, inline)
	}
	return out
}

var managarmColor = regexp.MustCompile(`\x1b\[[0-9;]*m`)

var managarmOopses = append([]*oops{
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
}, commonOopses...)
