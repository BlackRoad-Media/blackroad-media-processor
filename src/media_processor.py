#!/usr/bin/env python3
"""BlackRoad Media Processor - Analyse, organise and manage media files.

No ffmpeg required: uses file headers, struct, and heuristics.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import struct
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DB_PATH = Path.home() / ".blackroad" / "media_processor.db"

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class MediaFile:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    path: str = ""
    type: str = "unknown"      # video | audio | image | unknown
    size_mb: float = 0.0
    duration_secs: Optional[float] = None
    width: Optional[int] = None
    height: Optional[int] = None
    codec: Optional[str] = None
    mime_type: str = "application/octet-stream"
    md5: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class ThumbnailInfo:
    media_id: str = ""
    suggested_time_secs: float = 0.0
    width: int = 320
    height: int = 180
    format: str = "jpeg"


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def _conn(path: Path = DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    _init_db(con)
    return con


def _init_db(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS media_files (
            id           TEXT PRIMARY KEY,
            path         TEXT NOT NULL,
            type         TEXT NOT NULL DEFAULT 'unknown',
            size_mb      REAL DEFAULT 0,
            duration_secs REAL,
            width        INTEGER,
            height       INTEGER,
            codec        TEXT,
            mime_type    TEXT DEFAULT 'application/octet-stream',
            md5          TEXT,
            created_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS jobs (
            id          TEXT PRIMARY KEY,
            type        TEXT NOT NULL,
            input_path  TEXT NOT NULL,
            output_path TEXT,
            status      TEXT DEFAULT 'pending',
            result      TEXT DEFAULT '{}',
            created_at  TEXT NOT NULL,
            finished_at TEXT
        );
    """)
    con.commit()


# ---------------------------------------------------------------------------
# File-header analysis helpers
# ---------------------------------------------------------------------------

_MAGIC: List[Tuple[bytes, str, str, Optional[str]]] = [
    # (magic bytes at offset 0, media_type, mime_type, codec)
    (b"\xff\xd8\xff",        "image", "image/jpeg",         "jpeg"),
    (b"\x89PNG\r\n\x1a\n",   "image", "image/png",          "png"),
    (b"GIF87a",               "image", "image/gif",          "gif"),
    (b"GIF89a",               "image", "image/gif",          "gif"),
    (b"RIFF",                 "audio", "audio/wav",          "pcm"),
    (b"ID3",                  "audio", "audio/mpeg",         "mp3"),
    (b"\xff\xfb",             "audio", "audio/mpeg",         "mp3"),
    (b"\xff\xf3",             "audio", "audio/mpeg",         "mp3"),
    (b"fLaC",                 "audio", "audio/flac",         "flac"),
    (b"OggS",                 "audio", "audio/ogg",          "vorbis"),
    (b"\x1aE\xdf\xa3",        "video", "video/webm",         "vp8"),
]

# MP4/MOV containers: ftyp box at offset 4
_MP4_BRANDS = {b"ftyp", b"moov", b"mdat"}

_EXT_MAP: Dict[str, Tuple[str, str]] = {
    ".mp4":  ("video", "video/mp4"),
    ".mov":  ("video", "video/quicktime"),
    ".avi":  ("video", "video/x-msvideo"),
    ".mkv":  ("video", "video/x-matroska"),
    ".webm": ("video", "video/webm"),
    ".mp3":  ("audio", "audio/mpeg"),
    ".wav":  ("audio", "audio/wav"),
    ".flac": ("audio", "audio/flac"),
    ".aac":  ("audio", "audio/aac"),
    ".ogg":  ("audio", "audio/ogg"),
    ".jpg":  ("image", "image/jpeg"),
    ".jpeg": ("image", "image/jpeg"),
    ".png":  ("image", "image/png"),
    ".gif":  ("image", "image/gif"),
    ".webp": ("image", "image/webp"),
    ".bmp":  ("image", "image/bmp"),
}


def _probe_magic(data: bytes) -> Tuple[str, str, Optional[str]]:
    """Return (media_type, mime_type, codec) from raw bytes."""
    for magic, mtype, mime, codec in _MAGIC:
        if data[:len(magic)] == magic:
            return mtype, mime, codec
    # MP4/MOV: box size (4 bytes) then brand
    if len(data) >= 8 and data[4:8] in _MP4_BRANDS:
        return "video", "video/mp4", "h264"
    return "unknown", "application/octet-stream", None


def _png_dimensions(data: bytes) -> Tuple[Optional[int], Optional[int]]:
    if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n":
        width = struct.unpack(">I", data[16:20])[0]
        height = struct.unpack(">I", data[20:24])[0]
        return width, height
    return None, None


def _jpeg_dimensions(path: str) -> Tuple[Optional[int], Optional[int]]:
    """Walk JPEG segments to find SOF marker."""
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
        i = 2
        while i < len(data) - 8:
            if data[i] != 0xFF:
                break
            marker = data[i + 1]
            length = struct.unpack(">H", data[i + 2: i + 4])[0]
            if marker in (0xC0, 0xC2):  # SOF0 / SOF2
                height = struct.unpack(">H", data[i + 5: i + 7])[0]
                width = struct.unpack(">H", data[i + 7: i + 9])[0]
                return width, height
            i += 2 + length
    except Exception:
        pass
    return None, None


def _md5(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

def analyze_file(path: str, db: Path = DB_PATH) -> MediaFile:
    """Analyse a media file using file headers + heuristics."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")

    size_mb = round(p.stat().st_size / (1024 * 1024), 4)
    ext = p.suffix.lower()

    with open(path, "rb") as f:
        header = f.read(512)

    media_type, mime, codec = _probe_magic(header)
    if media_type == "unknown" and ext in _EXT_MAP:
        media_type, mime = _EXT_MAP[ext]

    width, height = None, None
    if mime == "image/png":
        width, height = _png_dimensions(header)
    elif mime == "image/jpeg":
        width, height = _jpeg_dimensions(path)

    checksum = _md5(path)

    mf = MediaFile(
        path=str(p.resolve()),
        type=media_type,
        size_mb=size_mb,
        width=width,
        height=height,
        codec=codec,
        mime_type=mime,
        md5=checksum,
    )

    with _conn(db) as con:
        con.execute(
            "INSERT OR REPLACE INTO media_files VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                mf.id, mf.path, mf.type, mf.size_mb,
                mf.duration_secs, mf.width, mf.height,
                mf.codec, mf.mime_type, mf.md5, mf.created_at,
            ),
        )
    return mf


def create_thumbnail_info(media: MediaFile) -> ThumbnailInfo:
    """Return thumbnail generation metadata (no actual conversion)."""
    aspect = (media.width / media.height) if (media.width and media.height) else (16 / 9)
    thumb_width = 320
    thumb_height = max(1, round(thumb_width / aspect))
    suggested_time = (media.duration_secs / 4) if media.duration_secs else 0.0
    return ThumbnailInfo(
        media_id=media.id,
        suggested_time_secs=round(suggested_time, 2),
        width=thumb_width,
        height=thumb_height,
        format="jpeg" if media.type == "video" else "jpeg",
    )


def generate_manifest(files: List[MediaFile], fmt: str = "hls") -> dict:
    """Generate a streaming manifest descriptor (HLS or DASH-like)."""
    if fmt == "hls":
        playlists = []
        for mf in files:
            bw = int(mf.size_mb * 8 * 1024 / max(mf.duration_secs or 60, 1))
            playlists.append({
                "bandwidth": bw,
                "path": mf.path,
                "codecs": mf.codec or "avc1.42E01E,mp4a.40.2",
                "resolution": f"{mf.width or 1280}x{mf.height or 720}",
            })
        return {
            "format": "HLS",
            "version": 3,
            "playlists": playlists,
            "total_files": len(files),
        }
    return {
        "format": "DASH",
        "adaptation_sets": [{"id": mf.id, "path": mf.path} for mf in files],
    }


def batch_rename(directory: str, pattern: str, db: Path = DB_PATH) -> List[dict]:
    """Rename all media files in *directory* using *pattern*.

    Pattern supports: {name}, {index:03d}, {ext}, {date}
    """
    d = Path(directory)
    results = []
    for idx, fp in enumerate(sorted(d.iterdir()), start=1):
        if not fp.is_file():
            continue
        ext = fp.suffix.lower()
        if ext not in _EXT_MAP:
            continue
        date_str = datetime.fromtimestamp(fp.stat().st_mtime).strftime("%Y%m%d")
        new_name = pattern.format(
            name=fp.stem,
            index=idx,
            ext=ext.lstrip("."),
            date=date_str,
        )
        if not new_name.endswith(ext):
            new_name += ext
        new_path = fp.parent / new_name
        fp.rename(new_path)
        results.append({"old": str(fp), "new": str(new_path)})
    return results


def organize_by_date(source_dir: str, dest_dir: str, db: Path = DB_PATH) -> dict:
    """Move media files from *source_dir* into *dest_dir*/YYYY/MM/ subfolders."""
    src = Path(source_dir)
    dst = Path(dest_dir)
    moved, skipped = 0, 0
    for fp in src.rglob("*"):
        if not fp.is_file():
            continue
        if fp.suffix.lower() not in _EXT_MAP:
            skipped += 1
            continue
        mtime = datetime.fromtimestamp(fp.stat().st_mtime)
        target_dir = dst / str(mtime.year) / f"{mtime.month:02d}"
        target_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(fp), target_dir / fp.name)
        moved += 1
    return {"moved": moved, "skipped": skipped}


def duplicate_finder(directory: str, db: Path = DB_PATH) -> List[dict]:
    """Find duplicate media files by MD5 checksum."""
    d = Path(directory)
    seen: Dict[str, List[str]] = {}
    for fp in d.rglob("*"):
        if not fp.is_file() or fp.suffix.lower() not in _EXT_MAP:
            continue
        checksum = _md5(str(fp))
        seen.setdefault(checksum, []).append(str(fp))

    duplicates = []
    for checksum, paths in seen.items():
        if len(paths) > 1:
            duplicates.append({"md5": checksum, "files": paths, "count": len(paths)})
    return duplicates


def list_media(media_type: Optional[str] = None, db: Path = DB_PATH) -> List[dict]:
    with _conn(db) as con:
        if media_type:
            rows = con.execute(
                "SELECT * FROM media_files WHERE type=? ORDER BY created_at DESC",
                (media_type,),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM media_files ORDER BY created_at DESC"
            ).fetchall()
    return [dict(r) for r in rows]


def m3u8_playlist(streams: List[dict]) -> str:
    """Generate a simple M3U8 playlist string."""
    lines = ["#EXTM3U"]
    for s in streams:
        lines.append(f"#EXTINF:-1,{s.get('name', 'stream')}")
        lines.append(s.get("url", ""))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BlackRoad Media Processor")
    sub = p.add_subparsers(dest="cmd", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a media file")
    analyze.add_argument("path")

    manifest = sub.add_parser("manifest", help="Generate HLS/DASH manifest")
    manifest.add_argument("paths", nargs="+")
    manifest.add_argument("--format", default="hls", choices=["hls", "dash"])

    rename = sub.add_parser("rename", help="Batch rename media files")
    rename.add_argument("directory")
    rename.add_argument("--pattern", default="{index:04d}_{name}")

    organize = sub.add_parser("organize", help="Organize by date")
    organize.add_argument("source_dir")
    organize.add_argument("dest_dir")

    dupes = sub.add_parser("duplicates", help="Find duplicate files")
    dupes.add_argument("directory")

    lst = sub.add_parser("list", help="List analysed media")
    lst.add_argument("--type", dest="media_type", default=None)

    return p


def main(argv=None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "analyze":
        mf = analyze_file(args.path)
        print(json.dumps(asdict(mf), indent=2))

    elif args.cmd == "manifest":
        files = [analyze_file(p) for p in args.paths]
        manifest = generate_manifest(files, fmt=args.format)
        print(json.dumps(manifest, indent=2))

    elif args.cmd == "rename":
        results = batch_rename(args.directory, args.pattern)
        print(json.dumps(results, indent=2))

    elif args.cmd == "organize":
        result = organize_by_date(args.source_dir, args.dest_dir)
        print(json.dumps(result, indent=2))

    elif args.cmd == "duplicates":
        dupes = duplicate_finder(args.directory)
        print(json.dumps(dupes, indent=2))

    elif args.cmd == "list":
        print(json.dumps(list_media(args.media_type), indent=2))


if __name__ == "__main__":
    main()
