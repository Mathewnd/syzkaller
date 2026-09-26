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
)

type astral struct {
	*config
}

var (
	astralColor  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	astralMarker = regexp.MustCompile(`cpu[0-9]+: Oops\.$`)
	astralAssert = regexp.MustCompile(`^(.+):([^:]+):([0-9]+): (.+) failed$`)
	astralRIP    = regexp.MustCompile(`^rip: ([0-9a-fA-F]{16})(?:[ \t]|$)`)
)

func ctorAstral(cfg *config) (reporterImpl, []string, error) {
	return &astral{config: cfg}, nil, nil
}

func (ctx *astral) ContainsCrash(output []byte) bool {
	return ctx.findOops(output) != nil || containsCrash(output, commonOopses, ctx.ignores)
}

func (ctx *astral) Parse(output []byte) *Report {
	astralReport := ctx.findOops(output)
	commonReport := simpleLineParser(output, commonOopses, nil, ctx.ignores)
	if commonReport != nil && (astralReport == nil || commonReport.StartPos < astralReport.StartPos) {
		return commonReport
	}
	if astralReport != nil && !strings.HasPrefix(astralReport.Title, "panic: assertion failed at ") &&
		ctx.kernelDirs.Obj != "" {
		symb := symbolizer.Make(ctx.target)
		defer symb.Close()
		ctx.symbolizeFault(astralReport, symb.Symbolize)
	}
	return astralReport
}

func (ctx *astral) symbolizeFault(rep *Report,
	symbFunc func(string, ...uint64) ([]symbolizer.Frame, error)) {
	_, context, _ := bytes.Cut(rep.Report, []byte{'\n'})
	for _, line := range bytes.Split(context, []byte{'\n'}) {
		clean := bytes.TrimSuffix(astralColor.ReplaceAll(line, nil), []byte{'\r'})
		if astralMarker.Match(clean) {
			return
		}
		match := astralRIP.FindSubmatch(clean)
		if match == nil {
			continue
		}
		pc, err := strconv.ParseUint(string(match[1]), 16, 64)
		if err != nil {
			return
		}
		// RIP is the faulting instruction, not a return address.
		frames, err := symbFunc(filepath.Join(ctx.kernelDirs.Obj, ctx.target.KernelObject), pc)
		if err != nil {
			return
		}
		for _, frame := range frames {
			if frame.File == "" || frame.File == "??" || frame.Line <= 0 ||
				frame.Func == "" || frame.Func == "??" {
				continue
			}
			file := frame.File
			for _, root := range []string{ctx.kernelDirs.BuildSrc, ctx.kernelDirs.Src} {
				if root != "" {
					file = strings.TrimPrefix(file, filepath.Clean(root)+"/")
				}
			}
			rep.Title = fmt.Sprintf("%s at %s in %s", rep.Title, file, frame.Func)
			return
		}
		return
	}
}

func (ctx *astral) Symbolize(rep *Report) error {
	return nil
}

func (ctx *astral) findOops(output []byte) *Report {
	for pos := 0; pos < len(output); {
		end := bytes.IndexByte(output[pos:], '\n')
		if end == -1 {
			end = len(output)
		} else {
			end += pos
		}
		line := output[pos:end]
		clean := bytes.TrimSuffix(astralColor.ReplaceAll(line, nil), []byte{'\r'})
		marker := astralMarker.FindIndex(clean)
		if marker != nil && !matchesAny(line, ctx.ignores) && !matchesAny(clean, ctx.ignores) &&
			!matchesAny(clean[marker[0]:], ctx.ignores) {
			title := "panic: Oops."
			if end < len(output) {
				message := output[end+1:]
				if newline := bytes.IndexByte(message, '\n'); newline != -1 {
					message = message[:newline]
				}
				message = bytes.TrimSpace(astralColor.ReplaceAll(message, nil))
				if assertion := astralAssert.FindSubmatch(message); assertion != nil {
					title = fmt.Sprintf("panic: assertion failed at %s in %s", assertion[1], assertion[2])
				} else if len(message) != 0 && !bytes.HasPrefix(message, []byte("cr2:")) &&
					!astralMarker.Match(message) {
					title = "panic: " + string(message)
				}
			}
			return &Report{
				Title:    title,
				Type:     crash.TitleToType(title),
				Report:   output[pos:],
				Output:   output,
				StartPos: pos,
				EndPos:   end,
			}
		}
		pos = end + 1
	}
	return nil
}
