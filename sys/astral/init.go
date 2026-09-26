package astral

import (
    "github.com/google/syzkaller/prog"
    "github.com/google/syzkaller/sys/targets"
)

func InitTarget(target *prog.Target) {
    unix := targets.MakeUnixNeutralizer(target)

    target.MakeDataMmap =
        targets.MakePosixMmap(target, true, false)

    target.Neutralize = unix.Neutralize
}
