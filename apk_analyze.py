#!/usr/bin/env python3
"""
Static APK triage (no execution).

Outputs:
  - package name, version, SDK info
  - permissions + exported components
  - quick IOC-style string hits from DEX
  - basic Flutter/native hints (if libapp.so present)
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Iterable


IOC_PATTERNS = {
    "url": re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
    "ws": re.compile(r"\bwss?://[^\s\"'<>]+", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b[a-zA-Z0-9.-]+\.(?:com|net|org|io|ru|cn|ir|ua|dev|app|xyz|top|info)\b", re.IGNORECASE),
}


@dataclass
class Component:
    kind: str
    name: str
    exported: bool | None
    permission: str | None
    intent_filters: list[dict]


def uniq(seq: Iterable[str]) -> list[str]:
    seen = set()
    out = []
    for s in seq:
        if s not in seen:
            out.append(s)
            seen.add(s)
    return out


def scan_iocs(strings: Iterable[str], limit_each: int = 200) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {k: [] for k in IOC_PATTERNS.keys()}
    for s in strings:
        for k, rx in IOC_PATTERNS.items():
            if len(hits[k]) >= limit_each:
                continue
            if rx.search(s):
                hits[k].append(s)
    # de-dupe but keep order
    for k in hits:
        hits[k] = uniq(hits[k])
    return hits


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} /path/to/app.apk", file=sys.stderr)
        return 2

    apk_path = sys.argv[1]
    if not os.path.isfile(apk_path):
        print(f"Not a file: {apk_path}", file=sys.stderr)
        return 2

    try:
        from androguard.misc import AnalyzeAPK
    except Exception as e:
        print(f"Failed to import androguard: {e}", file=sys.stderr)
        return 3

    # Androguard uses loguru and can be extremely verbose. Try to silence it.
    try:
        from loguru import logger  # type: ignore

        logger.remove()
    except Exception:
        pass

    a, d, dx = AnalyzeAPK(apk_path)

    out: dict = {
        "apk_path": apk_path,
        "package": a.get_package(),
        "version_name": a.get_androidversion_name(),
        "version_code": a.get_androidversion_code(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "max_sdk": a.get_max_sdk_version(),
        "app_name": None,
        # In androguard 4.x, requested permissions are split into AOSP vs third-party.
        "permissions_declared": sorted(set(a.get_declared_permissions() or [])),
        "permissions_requested_aosp": sorted(set(a.get_requested_aosp_permissions() or [])),
        "permissions_requested_third_party": sorted(set(a.get_requested_third_party_permissions() or [])),
        "permissions_requested_all": sorted(set(a.get_permissions() or [])),
        "uses_features": sorted(set(a.get_features() or [])),
        "components": [],
        "dex_summary": {},
        "dex_iocs": {},
        "flutter_hints": {},
    }

    # App label (best-effort; may fail without resource decoding)
    try:
        out["app_name"] = a.get_app_name()
    except Exception:
        out["app_name"] = None

    def collect_intent_filters(node) -> list[dict]:
        res = []
        for ifilt in node.findall("intent-filter"):
            actions = [x.get("{http://schemas.android.com/apk/res/android}name") for x in ifilt.findall("action")]
            cats = [x.get("{http://schemas.android.com/apk/res/android}name") for x in ifilt.findall("category")]
            datas = []
            for x in ifilt.findall("data"):
                dct = {}
                for k, v in x.attrib.items():
                    dct[k] = v
                datas.append(dct)
            res.append({"actions": [x for x in actions if x], "categories": [x for x in cats if x], "data": datas})
        return res

    # Parse manifest XML tree as exposed by androguard
    m = a.get_android_manifest_xml()
    app = m.find("application")
    if app is not None:
        android_ns = "{http://schemas.android.com/apk/res/android}"

        def comp_nodes(tag: str) -> list[Component]:
            comps: list[Component] = []
            for node in app.findall(tag):
                name = node.get(android_ns + "name") or ""
                exported_raw = node.get(android_ns + "exported")
                exported = None if exported_raw is None else exported_raw.lower() == "true"
                perm = node.get(android_ns + "permission")
                comps.append(
                    Component(
                        kind=tag,
                        name=name,
                        exported=exported,
                        permission=perm,
                        intent_filters=collect_intent_filters(node),
                    )
                )
            return comps

        comps = []
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            comps.extend(comp_nodes(tag))

        out["components"] = [asdict(c) for c in comps]

    # DEX quick summary + IOC scanning
    try:
        classes = list(dx.get_classes()) if dx is not None else []
        methods = list(dx.get_methods()) if dx is not None else []
        strings = list(dx.get_strings()) if dx is not None else []
        out["dex_summary"] = {
            "classes": len(classes),
            "methods": len(methods),
            "strings": len(strings),
        }
        # Keep scan fast: only consider reasonably sized strings
        scan_space = (s for s in strings if isinstance(s, str) and 6 <= len(s) <= 4000)
        out["dex_iocs"] = scan_iocs(scan_space, limit_each=250)
    except Exception as e:
        out["dex_summary"] = {"error": str(e)}

    # Flutter/native hints (best-effort; path is based on common layout)
    base_dir = os.path.dirname(os.path.abspath(apk_path))
    unpack_guess = os.path.join(base_dir, "8i3bsx_unpacked", "lib", "arm64-v8a", "libapp.so")
    if os.path.isfile(unpack_guess):
        try:
            with open(unpack_guess, "rb") as f:
                blob = f.read(8 * 1024 * 1024)  # read first 8MB only
            # common markers seen in Flutter AOT snapshots / embedding
            markers = [
                b"kDartIsolateSnapshotData",
                b"kDartIsolateSnapshotInstructions",
                b"FlutterEngine",
                b"Dart_InitializeApiDL",
                b"dart:io",
                b"dart:core",
            ]
            out["flutter_hints"] = {
                "libapp_so_path": unpack_guess,
                "markers_present": {m.decode("utf-8", "ignore"): (m in blob) for m in markers},
            }
        except Exception as e:
            out["flutter_hints"] = {"libapp_so_path": unpack_guess, "error": str(e)}
    else:
        out["flutter_hints"] = {"libapp_so_path": unpack_guess, "note": "libapp.so not found at guessed path"}

    print(json.dumps(out, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

