// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

func newAstralReporter(t *testing.T, ignores ...string) *Reporter {
	t.Helper()
	reporter, err := NewReporter(&mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   targets.Astral,
			TargetArch: targets.AMD64,
			SysTarget:  targets.Get(targets.Astral, targets.AMD64),
		},
		Ignores: ignores,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reporter
}

func TestAstralReporter(t *testing.T) {
	reporter := newAstralReporter(t)
	tests := []struct {
		name  string
		log   string
		title string
	}{
		{
			name:  "assertion after marker",
			log:   "booted\ncpu12: Oops.\n\x1b[91mkernel-src/fs/vfs.c:openat:70: vnode failed\x1b[0m\n",
			title: "panic: assertion failed at kernel-src/fs/vfs.c in openat",
		},
		{
			name:  "assertion with a literal number",
			log:   "cpu0: Oops.\n\x1b[91msys/syscalls/open.c:syscall_openat:140: fd_close(newfd) == 0 failed\x1b[0m\n",
			title: "panic: assertion failed at sys/syscalls/open.c in syscall_openat",
		},
		{
			name:  "assertion after source line change",
			log:   "cpu1: Oops.\n\x1b[91msys/syscalls/open.c:syscall_openat:141: fd_close(newfd) == 0 failed\x1b[0m\r\n",
			title: "panic: assertion failed at sys/syscalls/open.c in syscall_openat",
		},
		{
			name:  "message after marker",
			log:   "booted\ncpu2: Oops.\nPage Fault\ncr2: 0000000000000000\n",
			title: "panic: Page Fault",
		},
		{
			name:  "marker on a half-written line",
			log:   "mm: no such space or space accesscpu0: Oops.\nSMAP violation\ncr2: 0000000000000020  gs: 0000\n",
			title: "panic: SMAP violation",
		},
		{
			name:  "no message",
			log:   "cpu0: Oops.\ncr2: 0000000000000000\n",
			title: "panic: Oops.",
		},
		{
			name:  "marker at end",
			log:   "cpu9: Oops.",
			title: "panic: Oops.",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := []byte(test.log)
			if !reporter.ContainsCrash(output) {
				t.Fatal("crash not detected")
			}
			rep := reporter.Parse(output)
			if rep == nil || rep.Title != test.title {
				t.Fatalf("title: got %v, want %q", rep, test.title)
			}
			if rep.Type != crash.DoS || !bytes.Equal(rep.Output, output) {
				t.Fatalf("bad report type or output: %v", rep)
			}
			if rep.SkipPos <= rep.StartPos || rep.SkipPos > rep.EndPos {
				t.Fatalf("invalid report positions: %+v", rep)
			}
			again := reporter.ParseFrom(output, rep.StartPos)
			if again == nil || again.Title != rep.Title || again.StartPos != rep.StartPos {
				t.Fatalf("ParseFrom changed report: %v", again)
			}
			if err := reporter.Symbolize(rep); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAstralReporterBoundaries(t *testing.T) {
	reporter := newAstralReporter(t)
	for _, output := range []string{
		"cpuX: Oops.\n",
		"prefix cpu3: Oops. trailing text\n",
		"cpu3: Oops.extra\n",
		"Oops.\n",
	} {
		if reporter.ContainsCrash([]byte(output)) || reporter.Parse([]byte(output)) != nil {
			t.Fatalf("false crash match: %q", output)
		}
	}
	common := []byte("SYZFATAL: executor failed\ncpu3: Oops.\nPage Fault\n")
	commonReport := reporter.Parse(common)
	if !reporter.ContainsCrash(common) || commonReport == nil || commonReport.StartPos != 0 {
		t.Fatal("shared crash marker was not selected first")
	}
	halfLine := []byte("booted\nmm: no such space or space accesscpu0: Oops.\nSMAP violation\n")
	halfLineReport := reporter.Parse(halfLine)
	if halfLineReport == nil || halfLineReport.StartPos != len("booted\n") ||
		!bytes.HasPrefix(halfLineReport.Report, []byte("mm: no such space or space access")) {
		t.Fatalf("half-written line was lost: %v", halfLineReport)
	}
	if ignored := newAstralReporter(t, `^cpu0: Oops\.$`); ignored.ContainsCrash(halfLine) ||
		ignored.Parse(halfLine) != nil {
		t.Fatal("ignored marker on half-written line was reported")
	}

	output := []byte("booted\ncpu12: Oops.\n" +
		"\x1b[91mkernel-src/fs/vfs.c:openat:70: vnode failed\x1b[0m\n" +
		"cpu2: Oops.\nPage Fault\n")
	reports := ParseAll(reporter, output)
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want 2", len(reports))
	}
	if reports[0].StartPos != len("booted\n") || !strings.HasPrefix(string(reports[0].Report), "cpu12: Oops.\n") ||
		reports[0].SkipPos != bytes.Index(output, []byte("\n\x1b[91m")) ||
		reports[0].Title != "panic: assertion failed at kernel-src/fs/vfs.c in openat" ||
		!bytes.Contains(reports[0].Report, []byte("vnode failed\x1b[0m\n")) {
		t.Fatalf("assertion report lost context or skipped wrong line: %+v", reports[0])
	}
	if reports[1].Title != "panic: Page Fault" {
		t.Fatalf("second report title: %q", reports[1].Title)
	}

	ignored := newAstralReporter(t, `^cpu12: Oops\.$`)
	if ignored.ContainsCrash(output[:reports[0].EndPos]) || ignored.Parse(output[:reports[0].EndPos]) != nil {
		t.Fatal("ignored colored Oops was reported")
	}
}

func TestAstralFaultLocation(t *testing.T) {
	const rip = "rip: ffffffff800d2820 rsp: ffff800000001000\n"
	const context = "cr2: 0000000000000020  gs: 0000\n" + rip
	frame := symbolizer.Frame{
		File: "/build_dir/builds/astral/mm/cache.c", Line: 313, Func: "sync_page",
	}
	tests := []struct {
		name   string
		log    string
		frames []symbolizer.Frame
		err    error
		title  string
		lookup bool
	}{
		{
			name: "faulting instruction", log: "cpu0: Oops.\nSMAP violation\n" + context,
			frames: []symbolizer.Frame{frame}, lookup: true,
			title: "panic: SMAP violation at mm/cache.c in sync_page",
		},
		{
			name: "source line change", log: "cpu0: Oops.\nSMAP violation\n" + context,
			frames: []symbolizer.Frame{{File: frame.File, Line: 314, Func: frame.Func}}, lookup: true,
			title: "panic: SMAP violation at mm/cache.c in sync_page",
		},
		{
			name: "innermost inline frame", log: "cpu0: Oops.\nSMAP violation\n" + context,
			frames: []symbolizer.Frame{
				{File: "/build_dir/builds/astral/mm/cache.c", Line: 88, Func: "remove_page", Inline: true},
				frame,
			}, lookup: true,
			title: "panic: SMAP violation at mm/cache.c in remove_page",
		},
		{
			name: "first usable frame", log: "cpu0: Oops.\nSMAP violation\n" + context,
			frames: []symbolizer.Frame{
				{File: frame.File, Line: -1, Func: "remove_page", Inline: true}, frame,
			}, lookup: true,
			title: "panic: SMAP violation at mm/cache.c in sync_page",
		},
		{
			name: "source root", log: "cpu0: Oops.\nSMAP violation\n" + context,
			frames: []symbolizer.Frame{{File: "/src/astral/mm/cache.c", Line: 313, Func: frame.Func}},
			lookup: true, title: "panic: SMAP violation at mm/cache.c in sync_page",
		},
		{
			name: "root directory boundary", log: "cpu0: Oops.\nSMAP violation\n" + context,
			frames: []symbolizer.Frame{
				{File: "/build_dir/builds/astral-other/mm/cache.c", Line: 313, Func: frame.Func},
			}, lookup: true,
			title: "panic: SMAP violation at /build_dir/builds/astral-other/mm/cache.c in sync_page",
		},
		{
			name: "ANSI and CRLF", log: "booted\r\n\x1b[91mprefixcpu1: Oops.\x1b[0m\r\n" +
				"SMAP violation\r\n\x1b[91mrip: FFFFFFFF800D2820 rsp: ffff800000001000\x1b[0m\r\n",
			frames: []symbolizer.Frame{frame}, lookup: true,
			title: "panic: SMAP violation at mm/cache.c in sync_page",
		},
		{
			name: "message normalization", log: "cpu0: Oops.\nfault 42 at 0x12345678\n" + context,
			frames: []symbolizer.Frame{frame}, lookup: true,
			title: "panic: fault NUM at ADDR at mm/cache.c in sync_page",
		},
		{
			name: "no message", log: "cpu0: Oops.\n" + context,
			frames: []symbolizer.Frame{frame}, lookup: true,
			title: "panic: Oops. at mm/cache.c in sync_page",
		},
		{
			name: "no context", log: "cpu0: Oops.\nSMAP violation\n",
			title: "panic: SMAP violation",
		},
		{
			name: "truncated RIP", log: "cpu0: Oops.\nSMAP violation\nrip: ffffffff800d28",
			title: "panic: SMAP violation",
		},
		{
			name: "malformed RIP", log: "cpu0: Oops.\nSMAP violation\nrip: ffffffff800d2820garbage\n",
			title: "panic: SMAP violation",
		},
		{
			name: "next panic context", log: "cpu0: Oops.\nSMAP violation\n" +
				"\x1b[91mprefixcpu1: Oops.\x1b[0m\r\nPage Fault\n" + context,
			title: "panic: SMAP violation",
		},
		{
			name: "unknown PC", log: "cpu0: Oops.\nSMAP violation\n" + context,
			lookup: true, title: "panic: SMAP violation",
		},
		{
			name: "no usable source location", log: "cpu0: Oops.\nSMAP violation\n" + context,
			frames: []symbolizer.Frame{
				{File: "??", Line: 313, Func: frame.Func},
				{File: frame.File, Line: 0, Func: frame.Func},
				{File: frame.File, Line: 313, Func: "??"},
			}, lookup: true, title: "panic: SMAP violation",
		},
		{
			name: "lookup failure", log: "cpu0: Oops.\nSMAP violation\n" + context,
			err: fmt.Errorf("symbolization failed"), lookup: true, title: "panic: SMAP violation",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reporter := newAstralReporter(t)
			output := []byte(test.log)
			rep := reporter.Parse(output)
			if rep == nil {
				t.Fatal("crash not detected")
			}
			before := *rep
			ctx := reporter.impl.(*astral)
			ctx.kernelDirs = mgrconfig.KernelDirs{
				Obj: "/obj", BuildSrc: "/build_dir/builds/astral", Src: "/src/astral",
			}
			called := false
			ctx.symbolizeFault(rep, func(bin string, pcs ...uint64) ([]symbolizer.Frame, error) {
				called = true
				if bin != filepath.Join("/obj", ctx.target.KernelObject) || len(pcs) != 1 ||
					pcs[0] != 0xffffffff800d2820 {
					t.Fatalf("wrong ELF or fault PC: %q %x", bin, pcs)
				}
				return test.frames, test.err
			})
			rep.Title = sanitizeTitle(replaceTable(dynamicTitleReplacement, rep.Title))
			if called != test.lookup || rep.Title != test.title {
				t.Fatalf("lookup=%v, title=%q; want lookup=%v, title=%q", called, rep.Title, test.lookup, test.title)
			}
			if !bytes.Equal(rep.Output, output) || !bytes.Equal(rep.Report, before.Report) ||
				rep.StartPos != before.StartPos || rep.EndPos != before.EndPos || rep.SkipPos != before.SkipPos {
				t.Fatal("symbolization changed raw output or report positions")
			}
		})
	}
}

func TestAstralFaultLookupBoundaries(t *testing.T) {
	reporter := newAstralReporter(t)
	ctx := reporter.impl.(*astral)
	calls := 0
	target := *ctx.target
	ctx.target = &target
	ctx.target.Addr2Line = func() (string, error) {
		calls++
		return "", fmt.Errorf("addr2line unavailable")
	}
	output := []byte("cpu0: Oops.\nSMAP violation\nrip: ffffffff800d2820 rsp: ffff800000001000\n")
	if rep := reporter.Parse(output); rep == nil || rep.Title != "panic: SMAP violation" || calls != 0 {
		t.Fatal("unconfigured symbols changed the title or invoked addr2line")
	}
	ctx.kernelDirs.Obj = "/obj"
	if !reporter.ContainsCrash(output) || calls != 0 {
		t.Fatal("ContainsCrash invoked addr2line or missed the crash")
	}
	if rep := reporter.Parse(output); rep == nil || rep.Title != "panic: SMAP violation" || calls != 1 {
		t.Fatal("Parse did not attempt symbolization or changed the title on failure")
	}
	for _, log := range []string{
		"cpu0: Oops.\n\x1b[91mmm/cache.c:sync_page:313: page != 0 failed\x1b[0m\nbacktrace:\n",
		"SYZFATAL: executor failed\n" + string(output),
	} {
		if rep := reporter.Parse([]byte(log)); rep == nil || calls != 1 {
			t.Fatal("assertion or shared crash marker invoked addr2line")
		}
	}
}
