"""
ingestion.py — Log Ingestion Engine for LogSentinel 2.0

Handles three ingestion modes:
  1. Multiple files at once
  2. Folder/directory watch (polls for new/changed files)
  3. Paste raw log text directly

Each ingestion session produces a list of IngestedSource objects,
each containing its own AnalysisReport so results can be shown side-by-side.
"""

import os
import time
import threading
from dataclasses import dataclass, field
from parser import analyse, AnalysisReport


SUPPORTED_EXTENSIONS = {".log", ".txt", ".csv", ".evtx", ".syslog", ""}


@dataclass
class IngestedSource:
    """Represents one analyzed log source."""
    name:    str                        # Display name (filename or "Pasted Text")
    path:    str | None                 # File path, or None if pasted text
    text:    str                        # Raw log content
    report:  AnalysisReport | None = None
    error:   str | None           = None
    size:    int                  = 0   # bytes


def ingest_files(paths: list[str]) -> list[IngestedSource]:
    """
    Load and analyze multiple log files.
    Returns one IngestedSource per file.
    """
    sources = []
    for path in paths:
        name = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            size = os.path.getsize(path)
            sources.append(IngestedSource(name=name, path=path,
                                          text=text, size=size))
        except Exception as e:
            sources.append(IngestedSource(name=name, path=path,
                                          text="", error=str(e)))
    return sources


def ingest_text(raw_text: str, label: str = "Pasted Text") -> IngestedSource:
    """
    Wrap pasted raw log text as an IngestedSource.
    """
    return IngestedSource(
        name=label,
        path=None,
        text=raw_text,
        size=len(raw_text.encode()),
    )


def ingest_folder(folder_path: str) -> list[IngestedSource]:
    """
    Load all supported log files from a folder (non-recursive).
    """
    sources = []
    try:
        entries = sorted(os.listdir(folder_path))
    except Exception as e:
        return [IngestedSource(name=folder_path, path=None, text="",
                               error=str(e))]

    for entry in entries:
        ext = os.path.splitext(entry)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            continue
        full_path = os.path.join(folder_path, entry)
        if not os.path.isfile(full_path):
            continue
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            size = os.path.getsize(full_path)
            sources.append(IngestedSource(name=entry, path=full_path,
                                          text=text, size=size))
        except Exception as e:
            sources.append(IngestedSource(name=entry, path=full_path,
                                          text="", error=str(e)))
    return sources


def analyze_sources(sources: list[IngestedSource],
                    keywords: list[str],
                    threshold: int,
                    on_progress=None) -> list[IngestedSource]:
    """
    Run analysis on each IngestedSource.
    Calls on_progress(index, total, source) after each completes.
    Returns the updated list with reports attached.
    """
    total = len(sources)
    for i, source in enumerate(sources):
        if source.error or not source.text.strip():
            source.error = source.error or "Empty file"
            if on_progress:
                on_progress(i + 1, total, source)
            continue
        try:
            source.report = analyse(source.text, keywords=keywords,
                                    brute_force_threshold=threshold)
        except Exception as e:
            source.error = str(e)
        if on_progress:
            on_progress(i + 1, total, source)
    return sources


# ── Folder Watcher ────────────────────────────────────────────────────────────

class FolderWatcher:
    """
    Watches a directory for new or modified log files.
    Calls on_new_file(path) when a change is detected.
    """

    def __init__(self, folder: str, on_new_file, interval: float = 3.0):
        self.folder      = folder
        self.on_new_file = on_new_file
        self.interval    = interval
        self._stop       = threading.Event()
        self._seen       = {}   # path -> mtime
        self._thread     = None

    def start(self):
        self._stop.clear()
        self._seen = self._snapshot()
        self._thread = threading.Thread(target=self._watch, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _snapshot(self) -> dict:
        snap = {}
        try:
            for entry in os.listdir(self.folder):
                ext = os.path.splitext(entry)[1].lower()
                if ext not in SUPPORTED_EXTENSIONS:
                    continue
                full = os.path.join(self.folder, entry)
                if os.path.isfile(full):
                    snap[full] = os.path.getmtime(full)
        except Exception:
            pass
        return snap

    def _watch(self):
        while not self._stop.is_set():
            time.sleep(self.interval)
            current = self._snapshot()
            for path, mtime in current.items():
                if path not in self._seen or self._seen[path] != mtime:
                    self.on_new_file(path)
            self._seen = current
