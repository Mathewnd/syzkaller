// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"

	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/ianlancetaylor/demangle"
)

type managarmServerCrash struct {
	program string
	faultIP uint64
}

// Limit crash log searches.
const managarmServerCrashLines = 20

func (ctx *managarm) findServerCrash(output []byte) (*Report, *managarmServerCrash) {
	rep := ctx.firstOops(output, 0, managarmServerOopses)
	if rep == nil {
		return nil, nil
	}

	server, kind := managarmCrashedServer(output[rep.StartPos:rep.EndPos])
	if server == "" {
		server = "??????"
	}
	srv := &managarmServerCrash{program: server}

	title := managarmServerCrashCause(rep, srv)
	if title == "" {
		title = managarmServerCrashKinds[kind]
	}

	rep.Title = srv.program + ": " + title
	rep.Type = crash.TitleToType(rep.Title)
	rep.Report = output[rep.StartPos:]
	return rep, srv
}

var managarmServerCrashKinds = map[string]string{
	"Signal sent by": "abort",
	"Panic in":       "panic",
	"Fault in":       "fault",
}

var (
	managarmServerCrashLine = regexp.MustCompile(`thor: (Signal sent by|Panic in|Fault in) server ([^\x1b\r\n]+)`)
	managarmProcessPanic    = regexp.MustCompile(`posix: User space panic in process ([^\x1b\r\n]+)`)
)

// Get the crash cause by looking before the actual crash line.
func managarmServerCrashCause(rep *Report, srv *managarmServerCrash) string {
	lines := bytes.SplitAfter(rep.Output[:rep.StartPos], []byte("\n"))
	pos := rep.StartPos

	for i := len(lines) - 1; i >= 0 && i >= len(lines)-managarmServerCrashLines; i-- {
		pos -= len(lines[i])
		line := managarmPlain(lines[i])
		if managarmProcessPanic.Match(line) || managarmServerCrashLine.Match(line) {
			// The lines before belong to another crash.
			return ""
		}

		var next []byte
		if i+1 < len(lines) {
			next = managarmPlain(lines[i+1])
		}

		if title := managarmCauseTitle(srv, line, next); title != "" {
			rep.StartPos = pos
			return title
		}
	}

	return ""
}

var (
	managarmServerPageFault = regexp.MustCompile(`^thor: Page fault in server, at [^,]*, faulting ip: (?:0x)?([0-9a-fA-F]+)`)
	managarmServerFault     = regexp.MustCompile(`^thor: ([a-z-]+) fault in server\.`)
	managarmServerLastIP    = regexp.MustCompile(`^Last ip: (?:0x)?([0-9a-fA-F]+)`)
	managarmAssert          = regexp.MustCompile(`In function (.*), file (.*):\d+: Assertion '.*' failed!`)
	managarmFrgAssert       = regexp.MustCompile(`^Assertion failed: `)
	managarmFrgAssertLoc    = regexp.MustCompile(`^In function (.*) at (.*):\d+$`)
	managarmEnsureLoc       = regexp.MustCompile(`^In function (.*), file (.*):\d+$`)
	managarmEnsure          = regexp.MustCompile(`^__ensure\(.*\) failed`)
	managarmHelCheck        = regexp.MustCompile(`^HEL_CHECK failed: (.*)$`)
	managarmHelCheckLoc     = regexp.MustCompile(`^\s*In file (.*) on line \d+$`)
	managarmUncaught        = regexp.MustCompile(`^terminate called after throwing an instance of '(.*)'$`)
	managarmUncaughtWhat    = regexp.MustCompile(`^\s*what\(\):\s*(.*)$`)
)

// Get title for server crash.
func managarmCauseTitle(srv *managarmServerCrash, line, next []byte) string {
	// page fault
	if match := managarmServerPageFault.FindSubmatch(line); match != nil {
		srv.faultIP, _ = strconv.ParseUint(string(match[1]), 16, 64)
		return "page fault"
	}

	// other faults
	if match := managarmServerFault.FindSubmatch(line); match != nil {
		if ip := managarmServerLastIP.FindSubmatch(next); ip != nil {
			srv.faultIP, _ = strconv.ParseUint(string(ip[1]), 16, 64)
		}
		return string(match[1]) + " fault"
	}

	// mlibc assert
	if match := managarmAssert.FindSubmatch(line); match != nil {
		return managarmTitleAt("assertion failed", managarmSourcePath(string(match[2])), string(match[1]))
	}

	// frigg assert
	if managarmFrgAssert.Match(line) {
		if loc := managarmFrgAssertLoc.FindSubmatch(next); loc != nil {
			return managarmTitleAt("assertion failed", managarmSourcePath(string(loc[2])), string(loc[1]))
		}
		return "assertion failed"
	}

	// mlibc __ensure()
	if match := managarmEnsureLoc.FindSubmatch(line); match != nil && managarmEnsure.Match(next) {
		return managarmTitleAt("__ensure failed", managarmSourcePath(string(match[2])), string(match[1]))
	}

	// HEL_CHECK()
	if match := managarmHelCheck.FindSubmatch(line); match != nil {
		title := fmt.Sprintf("HEL_CHECK(%s) failed", match[1])
		if loc := managarmHelCheckLoc.FindSubmatch(next); loc != nil {
			title += " at " + managarmSourcePath(string(loc[1]))
		}
		return title
	}

	// C++ exception
	if match := managarmUncaught.FindSubmatch(line); match != nil {
		if what := managarmUncaughtWhat.FindSubmatch(next); what != nil {
			return "uncaught exception: " + string(what[1])
		}
		return "uncaught exception of type " + string(match[1])
	}

	return ""
}

// In some cases, the actual crash cause is printed before the crash marker:
// 	thor: Page fault in server, at 0x8, faulting ip: 0x32e2fa
// 	[...]
// 	thor: Fault in server /usr/bin/posix-subsystem
// We need to get it to get accurate information about the crash.
func (ctx *managarm) recoverServerCrashCause(rep *Report,
	symbFunc func(string, ...uint64) ([]symbolizer.Frame, error)) {
	server, kind := managarmCrashedServer(rep.Report)
	if server == "" || rep.Title != server+": "+managarmServerCrashKinds[kind] {
		return
	}

	srv := &managarmServerCrash{program: server}
	crashPos := rep.StartPos
	title := managarmServerCrashCause(rep, srv)
	if title == "" {
		return
	}

	rep.Report = append(slices.Clone(rep.Output[rep.StartPos:crashPos]), rep.Report...)
	rep.Title = srv.program + ": " + title

	if symbFunc != nil {
		ctx.symbolizeServerTitle(rep, srv, symbFunc)
	}

	rep.Title = sanitizeTitle(replaceTable(dynamicTitleReplacement, rep.Title))
	rep.Type = crash.TitleToType(rep.Title)
}

// Check if a user (non-thor) crash happened.
func managarmUserCrashFollows(output []byte, pos int) bool {
	for i := 0; i < managarmServerCrashLines && pos < len(output); i++ {
		end := bytes.IndexByte(output[pos:], '\n')
		if end == -1 {
			end = len(output) - pos
		}

		line := managarmPlain(output[pos : pos+end])
		if managarmServerCrashLine.Match(line) || managarmProcessPanic.Match(line) {
			return true
		}

		pos += end + 1
	}

	return false
}

// Add location to title.
func (ctx *managarm) symbolizeServerTitle(rep *Report, srv *managarmServerCrash,
	symbFunc func(string, ...uint64) ([]symbolizer.Frame, error)) {
	if srv.faultIP == 0 {
		// Assertion failure.
		return
	}

	frames, err := symbFunc(filepath.Join(ctx.kernelDirs.Obj, srv.program), srv.faultIP)
	if err != nil {
		return
	}

	for _, frame := range frames {
		if frame.Func == "" || frame.Func == "??" || frame.File == "" || frame.File == "??" {
			continue
		}

		path := managarmSourcePath(frame.File, ctx.kernelDirs.BuildSrc, ctx.kernelDirs.Src)
		fn := demangle.Filter(frame.Func, demangle.NoParams, demangle.NoTemplateParams)
		rep.Title = managarmTitleAt(rep.Title, path, fn)
		rep.Type = crash.TitleToType(rep.Title)
		return
	}
}

// Get which server crashed and how.
func managarmCrashedServer(text []byte) (server, kind string) {
	match := managarmServerCrashLine.FindSubmatch(managarmColor.ReplaceAll(text, nil))
	if match == nil {
		return "", ""
	}

	server = filepath.Base(string(match[2]))
	kind = string(match[1])
	return server, kind
}

func managarmServerFaultIP(line []byte) [][]byte {
	if match := managarmServerPageFault.FindSubmatch(line); match != nil {
		return match
	}
	return managarmServerLastIP.FindSubmatch(line)
}

var managarmServerOopses = []*oops{
	{
		[]byte("thor: Signal sent by server "),
		[]oopsFormat{
			{
				title:        compile(`thor: Signal sent by server ([^\x1b\r\n]+)`),
				fmt:          "%[1]v: abort",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("thor: Panic in server "),
		[]oopsFormat{
			{
				title:        compile(`thor: Panic in server ([^\x1b\r\n]+)`),
				fmt:          "%[1]v: panic",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("thor: Fault in server "),
		[]oopsFormat{
			{
				title:        compile(`thor: Fault in server ([^\x1b\r\n]+)`),
				fmt:          "%[1]v: fault",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
}
