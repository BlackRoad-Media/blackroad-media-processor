"""Tests for media_processor."""

import hashlib
import sys
import struct
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from media_processor import (
    MediaFile,
    ThumbnailInfo,
    analyze_file,
    batch_rename,
    create_thumbnail_info,
    duplicate_finder,
    generate_manifest,
    m3u8_playlist,
    organize_by_date,
)


def _make_png(path: Path, width: int = 100, height: int = 80) -> Path:
    """Write a minimal valid PNG file."""
    import zlib

    def chunk(name: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + name + data
        return c + struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr = chunk(b"IHDR", ihdr_data)
    # minimal IDAT
    raw = b"\x00" + bytes([0] * width * 3)
    raw = raw * height
    idat = chunk(b"IDAT", zlib.compress(raw))
    iend = chunk(b"IEND", b"")
    path.write_bytes(signature + ihdr + idat + iend)
    return path


def _make_mp3(path: Path) -> Path:
    """Write a file with an ID3 magic header."""
    path.write_bytes(b"ID3" + bytes(200))
    return path


@pytest.fixture
def tmp_db(tmp_path):
    return tmp_path / "test.db"


def test_analyze_png(tmp_path, tmp_db):
    png = _make_png(tmp_path / "test.png", 200, 150)
    mf = analyze_file(str(png), db=tmp_db)
    assert mf.type == "image"
    assert mf.mime_type == "image/png"
    assert mf.width == 200
    assert mf.height == 150
    assert mf.md5 is not None


def test_analyze_mp3(tmp_path, tmp_db):
    mp3 = _make_mp3(tmp_path / "track.mp3")
    mf = analyze_file(str(mp3), db=tmp_db)
    assert mf.type == "audio"
    assert mf.codec == "mp3"


def test_analyze_file_not_found(tmp_db):
    with pytest.raises(FileNotFoundError):
        analyze_file("/nonexistent/file.mp4", db=tmp_db)


def test_create_thumbnail_info():
    mf = MediaFile(id="x", type="video", width=1920, height=1080, duration_secs=120.0)
    info = create_thumbnail_info(mf)
    assert info.media_id == "x"
    assert info.suggested_time_secs == 30.0
    assert info.width == 320
    assert info.height == 180


def test_generate_manifest_hls():
    files = [
        MediaFile(path="/a.mp4", type="video", size_mb=10.0, duration_secs=60, width=1280, height=720),
    ]
    manifest = generate_manifest(files, fmt="hls")
    assert manifest["format"] == "HLS"
    assert len(manifest["playlists"]) == 1


def test_duplicate_finder(tmp_path):
    content = b"duplicate file content here"
    (tmp_path / "a.mp3").write_bytes(b"ID3" + content)
    (tmp_path / "b.mp3").write_bytes(b"ID3" + content)
    (tmp_path / "c.mp3").write_bytes(b"ID3" + b"different")
    dupes = duplicate_finder(str(tmp_path))
    assert any(d["count"] == 2 for d in dupes)


def test_m3u8_playlist():
    streams = [
        {"name": "HD Stream", "url": "http://example.com/hd.m3u8"},
        {"name": "SD Stream", "url": "http://example.com/sd.m3u8"},
    ]
    playlist = m3u8_playlist(streams)
    assert playlist.startswith("#EXTM3U")
    assert "HD Stream" in playlist
    assert "http://example.com/hd.m3u8" in playlist


def test_organize_by_date(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    _make_png(src / "photo.png")
    result = organize_by_date(str(src), str(dst))
    assert result["moved"] >= 1
