import subprocess
import sys
from pathlib import Path
from typing import List

from nicegui import ui

ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable

def run_cmd(args: List[str]) -> str:
    result = subprocess.run(
        [PYTHON, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
    output = output.strip()
    if result.returncode != 0:
        raise RuntimeError(output or f"Command failed: {' '.join(args)}")
    return output or "Done."

@ui.page("/")
def main_page() -> None:
    ui.label("Open Vote Frontend").classes("text-h4")

if __name__ in {"__main__", "__mp_main__"}:
    ui.run(title="Open vote")
