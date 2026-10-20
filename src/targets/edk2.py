import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger

from targets.factory import TargetFactory

# Vendored third-party code, excluded from whole-codebase scans as in the
# CodeQL evaluation (submodules plus in-tree copies of external projects).
THIRD_PARTY_PREFIXES = (
    "CryptoPkg/Library/OpensslLib/openssl/",
    "CryptoPkg/Library/MbedTlsLib/mbedtls/",
    "UnitTestFrameworkPkg/Library/CmockaLib/cmocka/",
    "UnitTestFrameworkPkg/Library/GoogleTestLib/googletest/",
    "UnitTestFrameworkPkg/Library/SubhookLib/subhook/",
    "MdeModulePkg/Universal/RegularExpressionDxe/oniguruma/",
    "MdeModulePkg/Library/BrotliCustomDecompressLib/brotli/",
    "BaseTools/",
    "RedfishPkg/Library/JsonLib/jansson/",
    "MdePkg/Library/BaseFdtLib/libfdt/",
    "MdePkg/Library/MipiSysTLib/mipisyst/",
    "SecurityPkg/DeviceSecurity/SpdmLib/libspdm/",
)


class EDK2(TargetFactory):
    """
    TianoCore EDK2.

    EDK2 has no per-object make target, so every analysis tree is prebuilt
    once (scripts/build_tree.sh) and its compile_commands.json is recorded.
    "Checking out" a commit selects the prebuilt tree instead of rebuilding:
      - fix commit, is_before=True  -> data/trees/<CVE> (the buggy state)
      - anything else               -> data/trees/stable (edk2-stable202511,
                                       which every fix commit's tree equals)
    Objects are workspace-relative .c paths.
    """

    _target_type = "edk2"

    def __init__(self, repo_path: str, trees_dir: str):
        super().__init__(repo_path)
        self.trees_dir = Path(trees_dir)
        self.stable_tree = self.trees_dir / "stable"
        self._fix_to_tree: Dict[str, Path] = {}
        for ref in self.repo.references:
            if ref.path.startswith("refs/heads/knighter/"):
                cve = ref.path.rsplit("/", 1)[-1]
                self._fix_to_tree[ref.commit.hexsha] = self.trees_dir / cve
        self._compile_db: Dict[Path, Dict[str, dict]] = {}
        self.active_tree = self.stable_tree

    def tree_for(self, commit_id: str, is_before: bool = False) -> Path:
        if is_before:
            sha = self.repo.commit(commit_id).hexsha
            if sha not in self._fix_to_tree:
                raise ValueError(f"No buggy tree for commit {commit_id}")
            return self._fix_to_tree[sha]
        return self.stable_tree

    def checkout_commit(self, commit_id, is_before=False, **kwargs):
        self.active_tree = self.tree_for(commit_id, is_before)
        logger.info(f"EDK2: using tree {self.active_tree} for {commit_id} (before={is_before})")

    def compile_entries(self, tree: Optional[Path] = None) -> Dict[str, dict]:
        """Map each workspace-relative .c file to one compile command.

        stuart builds every package's DSC separately, so a library source is
        compiled once per package that uses it; the entry from the package that
        owns the file is preferred, otherwise the first one.
        """
        tree = Path(tree or self.active_tree)
        if tree in self._compile_db:
            return self._compile_db[tree]
        entries = json.loads((tree / "compile_commands.json").read_text())
        root = str(tree.resolve()) + "/"
        index: Dict[str, dict] = {}
        for e in entries:
            src = Path(e["file"])
            if not src.is_absolute():
                src = Path(e["directory"]) / src
            src = str(src.resolve())
            if not src.startswith(root) or not src.endswith(".c"):
                continue
            rel = src[len(root):]
            if rel.startswith("Build/"):
                continue  # AutoGen.c and other generated sources
            pkg = rel.split("/", 1)[0]
            out = " ".join(e.get("arguments", [])) or e.get("command", "")
            owned = f"/Build/{pkg}/" in out
            if rel not in index or (owned and not index[rel]["_owned"]):
                index[rel] = dict(e, file=src, _owned=owned)
        self._compile_db[tree] = index
        logger.info(f"EDK2: {len(index)} compiled C files in {tree}")
        return index

    def scan_objects(self, tree: Optional[Path] = None) -> List[str]:
        """First-party C files analysed by a whole-codebase scan."""
        return sorted(
            f for f in self.compile_entries(tree) if not f.startswith(THIRD_PARTY_PREFIXES)
        )

    def normalize_path(self, path: str) -> str:
        """Strip any analysis-tree root from a report path."""
        p = str(Path(path).resolve())
        for root in [self.stable_tree, *self._fix_to_tree.values()]:
            r = str(root.resolve()) + "/"
            if p.startswith(r):
                return p[len(r):]
        return path

    @staticmethod
    def get_object_name(file_name: str) -> str:
        return file_name

    @staticmethod
    def get_objects_from_patch(patch: str) -> List[str]:
        matches = re.findall(r"^--- a/(.*)$", patch, re.MULTILINE)
        return [m for m in matches if m.endswith(".c")]
