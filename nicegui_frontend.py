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

    with ui.tabs().classes("w-full") as tabs:
        authority_tab = ui.tab("Authority")
        voter_tab = ui.tab("Voter")

    with ui.tab_panels(tabs, value=authority_tab).classes("w-full"):
        with ui.tab_panel(authority_tab):
            ui.label("Authority panel coming soon...")

        with ui.tab_panel(voter_tab):
            ui.label("Voter panel coming soon...")

if __name__ in {"__main__", "__mp_main__"}:
    ui.run(title="Open vote")
