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
            # NEW: Authority inputs and command logic
            node = ui.input("Node URL", value="http://127.0.0.1:8001").classes("w-full")
            authority_id = ui.select(
                ["node1", "node2", "node3"], value="node1", label="Authority"
            ).classes("w-full")
            authority_out = ui.textarea("Output").props("readonly autogrow").classes("w-full")

            def run_authority(command: str) -> None:
                try:
                    args = ["authority_client.py", command, "--node", node.value]
                    if command in {"setup", "decrypt"}:
                        args += ["--authority", authority_id.value]
                    authority_out.value = run_cmd(args)
                    ui.notify(f"{command} succeeded")
                except Exception as exc:
                    authority_out.value = str(exc)
                    ui.notify(f"{command} failed", color="negative")

            with ui.row():
                ui.button("Setup", on_click=lambda: run_authority("setup"))
                ui.button("Open", on_click=lambda: run_authority("open"))
                ui.button("Close", on_click=lambda: run_authority("close"))
                ui.button("Decrypt", on_click=lambda: run_authority("decrypt"))
                ui.button("Tally", on_click=lambda: run_authority("tally"))

        with ui.tab_panel(voter_tab):
            ui.label("Voter panel coming soon...")

if __name__ in {"__main__", "__mp_main__"}:
    ui.run(title="Open vote")
