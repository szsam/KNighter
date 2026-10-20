"""EDK2 support for the CSA backend.

EDK2 trees are prebuilt with GCC (the toolchain of the CodeQL evaluation) and
their compile commands recorded with bear.  Each translation unit is analysed
with `clang --analyze` and the KNighter plugin, using the recorded flags minus
the GCC-only ones.  The analyzer options mirror KNighter's Linux scan-build
arguments (same disabled checker families, max-loop 4, HTML output).

Report layout matches the V8 backend, so extract_reports() works unchanged:
    <output_dir>/<timestamp>/<escaped source path>/report-*.html
"""

import glob
import os
import shlex
import subprocess as sp
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from loguru import logger

DISABLED_CHECKERS = ["core", "cplusplus", "deadcode", "unix", "nullability", "security"]
MAX_LOOP = 4
TU_TIMEOUT = 300

# GCC options clang rejects or that only matter for code generation.
DROP_FLAGS = {
    "-c", "-MMD", "-MD", "-flto", "-Werror", "-maccumulate-outgoing-args",
    "-fno-tree-loop-distribute-patterns", "-mno-mmx", "-mno-sse",
    "-fno-reorder-functions", "-fno-merge-constants", "-Wno-unused-but-set-variable",
    "-mabi=ms",
}
DROP_PREFIXES = ("-flto=", "-Wl,", "-Werror=", "--param", "-fno-tree-", "-mpreferred-stack-boundary")
DROP_WITH_ARG = {"-o", "-MF", "-MT", "-MQ"}


def _analyzer_args(plugin_path: str, out_dir: Path) -> List[str]:
    args = [
        "--analyze",
        "-Xclang", "-load", "-Xclang", plugin_path,
        "-Xclang", "-analyzer-checker=custom.SAGenTestChecker",
    ]
    for c in DISABLED_CHECKERS:
        args += ["-Xclang", f"-analyzer-disable-checker={c}"]
    args += [
        "-Xclang", "-analyzer-config", "-Xclang", f"max-loop={MAX_LOOP}",
        "-Xclang", "-analyzer-output=html",
        "-o", str(out_dir),
        "-w",
    ]
    return args


def _expand_response_files(argv: List[str], cwd: str) -> List[str]:
    """Inline @file arguments, which EDK2 uses for long command lines."""
    out: List[str] = []
    for a in argv:
        if a.startswith("@"):
            path = Path(cwd) / a[1:]
            if path.is_file():
                out += _expand_response_files(shlex.split(path.read_text()), cwd)
                continue
        out.append(a)
    return out


def translate_command(entry: dict, clang: str) -> List[str]:
    argv = entry.get("arguments") or shlex.split(entry["command"])
    argv = _expand_response_files(argv, entry["directory"])
    out: List[str] = [clang]
    skip = False
    for a in argv[1:]:
        if skip:
            skip = False
            continue
        if a in DROP_WITH_ARG:
            skip = True
            continue
        if a in DROP_FLAGS or a.startswith(DROP_PREFIXES):
            continue
        if a.endswith(".c") and os.path.abspath(os.path.join(entry["directory"], a)) == entry["file"]:
            continue  # re-appended last
        out.append(a)
    return out


def count_reports(report_dir: Path) -> int:
    return len(glob.glob(str(report_dir / "**" / "report-*.html"), recursive=True))


def analyze_tu(backend, rel: str, entry: dict, out_root: Path, timeout: int = TU_TIMEOUT
               ) -> Tuple[str, int, Optional[str]]:
    """Analyse one translation unit. Returns (status, num_reports, error)."""
    build_dir = (backend.backend_path / "build").absolute()
    # Absolute: clang runs in the module's build directory.
    out_dir = (out_root / rel.replace("/", "_")).absolute()
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = translate_command(entry, str(build_dir / "bin" / "clang"))
    plugin = os.environ.get("KNIGHTER_PLUGIN", "SAGenTest")
    cmd += _analyzer_args(str(build_dir / "lib" / f"{plugin}Plugin.so"), out_dir)
    cmd.append(entry["file"])
    try:
        res = sp.run(cmd, cwd=entry["directory"], capture_output=True, text=True, timeout=timeout)
    except sp.TimeoutExpired:
        return "timeout", count_reports(out_dir), f"timeout after {timeout}s"
    n = count_reports(out_dir)
    if "PLEASE submit a bug report" in res.stderr or res.returncode < 0:
        (out_dir / "crash.txt").write_text(" ".join(map(shlex.quote, cmd)) + "\n\n" + res.stderr)
        return "crash", n, res.stderr[-4000:]
    if res.returncode != 0:
        (out_dir / "error.txt").write_text(" ".join(map(shlex.quote, cmd)) + "\n\n" + res.stderr)
        return "error", n, res.stderr[-4000:]
    if n == 0:
        try:
            out_dir.rmdir()
        except OSError:
            pass
    return "ok", n, None


def validate_checker_edk2(backend, checker_code, commit_id, patch, target, skip_build_checker=False):
    """Same TP/TN scoring as ClangBackend._validate_checker_linux."""
    TP, TN = 0, 0
    if not skip_build_checker:
        backend.build_checker(checker_code, Path("tmp"), attempt=1)

    objects = target.get_objects_from_patch(patch)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S-%f")
    base = Path("tmp") / "edk2-validation" / stamp
    num_bug_obj = {}

    for phase, is_before in (("buggy", True), ("fixed", False)):
        tree = target.tree_for(commit_id, is_before=is_before)
        entries = target.compile_entries(tree)
        for obj in objects:
            entry = entries.get(obj)
            if entry is None:
                if phase == "buggy" or obj in num_bug_obj:
                    logger.warning(f"{phase}: {obj} is not compiled in {tree}")
                continue
            status, n, err = analyze_tu(backend, obj, entry, base / phase)
            logger.info(f"{phase}: {obj} status={status} reports={n}")
            if status == "timeout":
                # As in _validate_checker_linux, a timeout fails the attempt
                raise Exception(f"Analysis Timeout: {obj}")
            if status == "crash":
                return -2, -2
            if status == "error":
                logger.debug(err)
                return -1, -1
            if phase == "buggy":
                if n > 0:
                    num_bug_obj[obj] = n
                    TP += 1
            else:
                if n == 0:
                    TN += 1
                elif n < num_bug_obj.get(obj, 0) and n < 5:
                    TN += 1
                elif n > num_bug_obj.get(obj, 0):
                    TN -= 1
    logger.info(f"EDK2 validation: TP={TP}, TN={TN}")
    return TP, TN


def run_checker_edk2(backend, checker_code, commit_id, target, object_to_analyze=None,
                     jobs=32, output_dir="tmp", skip_build_checker=False, skip_checkout=False,
                     **kwargs) -> int:
    """Analyse one object, or every first-party TU of the selected tree."""
    output_dir = Path(output_dir)
    timeout = kwargs.get("timeout", 3600)
    if not skip_build_checker:
        rc, _ = backend.build_checker(checker_code, Path("tmp"), attempt=1)
        if rc != 0:
            raise Exception("Build failed, skipping analysis.")
    if not skip_checkout:
        target.checkout_commit(commit_id, is_before=kwargs.get("is_before", False))
    entries = target.compile_entries()
    objects = [object_to_analyze] if object_to_analyze else target.scan_objects()
    objects = [o for o in objects if o in entries]
    if not objects:
        logger.error(f"No compiled objects to analyse ({object_to_analyze})")
        return -999

    stamp_dir = output_dir / datetime.now().strftime("%Y-%m-%d-%H%M%S-%f")
    stamp_dir.mkdir(parents=True, exist_ok=True)
    deadline = datetime.now().timestamp() + timeout
    stats = {"ok": 0, "error": 0, "crash": 0, "timeout": 0, "skipped": 0}

    def work(rel):
        if datetime.now().timestamp() > deadline:
            return "skipped", 0, None
        return analyze_tu(backend, rel, entries[rel], stamp_dir)

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for status, _, _ in pool.map(work, objects):
            stats[status] += 1
    total = count_reports(stamp_dir)
    logger.info(f"EDK2 scan of {len(objects)} TUs: {stats}, {total} reports")
    (stamp_dir / "scan-stats.txt").write_text(f"{stats}\nreports={total}\n")
    if stats["skipped"]:
        logger.warning("Scan timed out before all TUs were analysed")
        return -1 if total == 0 else total
    return total
