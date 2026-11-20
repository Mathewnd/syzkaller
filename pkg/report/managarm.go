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

	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/ianlancetaylor/demangle"
)

type managarm struct {
	*config
}

func ctorManagarm(cfg *config) (reporterImpl, []string, error) {
	return &managarm{config: cfg}, nil, nil
}

type managarmCrashOrigin int

const (
	managarmNoCrash managarmCrashOrigin = iota
	managarmFromThor
	managarmFromServer
	managarmFromSyzkaller
)

func (ctx *managarm) ContainsCrash(output []byte) bool {
	_, origin, _ := ctx.findCrash(output)
	return origin != managarmNoCrash
}

// Get crash and create title.
func (ctx *managarm) Parse(output []byte) *Report {
	rep, origin, srv := ctx.findCrash(output)
	if origin == managarmNoCrash {
		return nil
	}

	if ctx.kernelDirs.Obj != "" {
		symb := symbolizer.Make(ctx.target)
		defer symb.Close()

		switch origin {
		case managarmFromThor:
			ctx.symbolizeThorTitle(rep, symb.Symbolize)
		case managarmFromServer:
			ctx.symbolizeServerTitle(rep, srv, symb.Symbolize)
		case managarmFromSyzkaller:
			// No address in the title.
		}
	}
	return rep
}

// Return the first thor/server/syzkaller crash in output.
// If there are multiple, the first one is used.
// If it is a server crash, also return the server that crashed.
func (ctx *managarm) findCrash(output []byte) (*Report, managarmCrashOrigin, *managarmServerCrash) {
	server, srv := ctx.findServerCrash(output)
	thor := ctx.findThorCrash(output)
	syzkaller := ctx.firstOops(output, 0, commonOopses)

	switch managarmFirstReport(server, thor, syzkaller) {
	case nil:
		return nil, managarmNoCrash, nil
	case server:
		return server, managarmFromServer, srv
	case thor:
		return thor, managarmFromThor, nil
	default:
		return syzkaller, managarmFromSyzkaller, nil
	}
}

// Returns the report that starts first in the output, nil if there is none.
func managarmFirstReport(reps ...*Report) *Report {
	var first *Report
	for _, rep := range reps {
		if rep != nil && (first == nil || rep.StartPos < first.StartPos) {
			first = rep
		}
	}

	return first
}

// Returns the first line in output[start:] that contains a crash in oopses.
func (ctx *managarm) firstOops(output []byte, start int, oopses []*oops) *Report {
	rep := simpleLineParser(output[start:], oopses, nil, ctx.ignores)
	if rep == nil {
		return nil
	}

	rep.Output = output
	rep.StartPos += start
	rep.EndPos += start
	rep.Report = output[rep.StartPos:]

	return rep
}

// Transform dwarf paths into repository-relative paths.
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

	// mlibc's ../../../src/mlibc/....
	file = strings.TrimPrefix(file, "src/")

	return file
}

// Clean up report using symbolizeLine.
func (ctx *managarm) Symbolize(rep *Report) error {
	if ctx.kernelDirs.Obj == "" {
		ctx.recoverServerCrashCause(rep, nil)
		return nil
	}

	symb := symbolizer.Make(ctx.target)

	defer symb.Close()

	ctx.recoverServerCrashCause(rep, symb.Symbolize)

	server, _ := managarmCrashedServer(rep.Report)

	var symbolized []byte
	for _, line := range bytes.SplitAfter(rep.Report, []byte("\n")) {
		symbolized = append(symbolized, ctx.symbolizeLine(symb.Symbolize, line, server)...)
	}
	rep.Report = symbolized

	return nil
}

// Clean up a line.
func (ctx *managarm) symbolizeLine(symbFunc func(string, ...uint64) ([]symbolizer.Frame, error),
	line []byte, server string) []byte {
	plain := managarmPlain(line)
	bin := filepath.Join(ctx.kernelDirs.Obj, ctx.target.KernelObject)
	match, isFrame := managarmThorIP(plain)

	if match == nil && server != "" {
		match = managarmServerFaultIP(plain)
		bin = filepath.Join(ctx.kernelDirs.Obj, server)
	}

	if match == nil {
		return line
	}

	pc, err := strconv.ParseUint(string(match[1]), 16, 64)
	if err != nil {
		return line
	}

	lookup := pc
	if isFrame {
		lookup--
	}

	frames, err := symbFunc(bin, lookup)
	if err != nil || len(frames) == 0 {
		return line
	}

	var out []byte
	if !isFrame {
		// Keep non-frame lines
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

// Remove any color ansi.
var managarmColor = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// Remove trailing newline.
func managarmPlain(line []byte) []byte {
	return managarmColor.ReplaceAll(bytes.TrimRight(line, "\r\n"), nil)
}

// Make the title pretty with location.
func managarmTitleAt(title, file, function string) string {
	return fmt.Sprintf("%v at %v in %v", title, file, function)
}
