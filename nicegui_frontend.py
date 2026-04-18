import subprocess
import sys
from pathlib import Path
from typing import List

from nicegui import ui

ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap');

* {
    font-family: 'JetBrains Mono', monospace !important;
    border-radius: 0 !important;
}

body {
    background: #000000;
    color: #e5e5e5;
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
}

.nicegui-content {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    width: 100%;
}

/* Override Quasar rounded corners */
.q-btn, .q-card, .q-field__control, .q-tab-panels, 
.q-tabs, .q-tab, .q-field, .q-select, .q-textarea {
    border-radius: 0 !important;
}

.q-card {
    background: transparent !important;
    box-shadow: none !important;
}

/* Custom components */
.mono-container {
    max-width: 900px;
    width: 100%
    padding: 48px 24px;
}

.mono-header {
    font-size: 14px;
    font-weight: 400;
    color: #666;
    text-transform: lowercase;
    letter-spacing: 0.02em;
    margin-bottom: 8px;
}

.mono-title {
    font-size: 32px;
    font-weight: 600;
    color: #fff;
    letter-spacing: -0.02em;
    line-height: 1.2;
}

.mono-subtitle {
    font-size: 14px;
    color: #666;
    margin-top: 12px;
}

.mono-section {
    border-top: 1px solid #222;
    padding-top: 32px;
    margin-top: 32px;
}

.mono-section-title {
    font-size: 12px;
    font-weight: 500;
    color: #666;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 20px;
}

.mono-label {
    font-size: 11px;
    color: #666;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 6px;
}

.mono-input .q-field__control {
    background: #0a0a0a !important;
    border: 1px solid #222 !important;
    min-height: 40px !important;
    padding: 0 12px !important;
}

.mono-input .q-field__control:hover {
    border-color: #333 !important;
}

.mono-input .q-field--focused .q-field__control {
    border-color: #fff !important;
}

.mono-input input, .mono-input textarea, .mono-input .q-field__native {
    color: #fff !important;
    font-size: 13px !important;
}

.mono-input .q-field__label {
    color: #666 !important;
    font-size: 12px !important;
}

.mono-btn {
    background: #0a0a0a !important;
    border: 1px solid #222 !important;
    color: #999 !important;
    font-size: 12px !important;
    font-weight: 500 !important;
    text-transform: lowercase !important;
    letter-spacing: 0.02em !important;
    padding: 10px 16px !important;
    min-height: 40px !important;
    transition: all 0.15s ease !important;
}

.mono-btn:hover {
    border-color: #fff !important;
    color: #fff !important;
    background: #111 !important;
}

.mono-btn-primary {
    background: #fff !important;
    border: 1px solid #fff !important;
    color: #000 !important;
}

.mono-btn-primary:hover {
    background: #e5e5e5 !important;
    border-color: #e5e5e5 !important;
}

.mono-output {
    background: #0a0a0a !important;
    border: 1px solid #222 !important;
    color: #888 !important;
    font-size: 12px !important;
    line-height: 1.6 !important;
    padding: 16px !important;
    min-height: 200px;
}

.mono-output .q-field__control {
    background: transparent !important;
    border: none !important;
}

.mono-tabs {
    border-bottom: 1px solid #222;
}

.mono-tabs .q-tab {
    color: #666 !important;
    font-size: 12px !important;
    text-transform: lowercase !important;
    letter-spacing: 0.02em !important;
    padding: 12px 20px !important;
    min-height: auto !important;
    opacity: 1 !important;
}

.mono-tabs .q-tab--active {
    color: #fff !important;
}

.mono-tabs .q-tab__indicator {
    background: #fff !important;
    height: 1px !important;
}

.mono-status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    color: #666;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.mono-status-dot {
    width: 6px;
    height: 6px;
    background: #333;
}

.mono-status-dot.active {
    background: #22c55e;
}

.mono-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
}

.mono-divider {
    height: 1px;
    background: #222;
    margin: 24px 0;
}

.mono-hint {
    font-size: 11px;
    color: #444;
    margin-top: 8px;
}

.mono-footer {
    font-size: 11px;
    color: #333;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

/* Hide notification icons (Material Icons not rendering properly) */
.q-notification__icon {
    display: none !important;
}

.q-notification {
    border-radius: 0 !important;
    font-size: 12px !important;
}

/* Terminal prompt style */
.mono-prompt {
    color: #666;
}

.mono-prompt::before {
    content: "> ";
    color: #444;
}
</style>
"""

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
    return output or "done."


@ui.page("/")
def main_page() -> None:
    ui.add_head_html(CUSTOM_CSS)
    ui.dark_mode().enable()

    with ui.column().classes("mono-container w-full"):
        ui.label("secure voting").classes("mono-header")
        ui.label("open vote").classes("mono-title")
        ui.label("decentralized, transparent, verifiable elections").classes("mono-subtitle")

        with ui.element("div").classes("mono-section"):
            with ui.tabs().classes("mono-tabs").props('dense no-caps indicator-color="white"') as tabs:
                authority_tab = ui.tab("authority")
                voter_tab = ui.tab("voter")

            with ui.tab_panels(tabs, value=authority_tab).classes("bg-transparent"):
                # Authority panel
                with ui.tab_panel(authority_tab).classes("p-0 pt-8"):
                    with ui.row().classes("items-center mb-8"):
                        ui.html('<div class="mono-status"><div class="mono-status-dot active"></div>system ready</div>')
                    with ui.row().classes("w-full gap-8 flex-wrap"):
                        with ui.column().classes("flex-1 min-w-[280px]"):
                            ui.label("configuration").classes("mono-section-title")

                            ui.label("node url").classes("mono-label")
                            node = ui.input(value="http://127.0.0.1:8001").classes("w-full mono-input mb-4").props('dark dense borderless')

                            ui.label("authority id").classes("mono-label")
                            authority_id = ui.select(
                                ["node1", "node2", "node3"],
                                value="node1"
                            ).classes("w-full mono-input mb-6").props('dark dense borderless options-dark dropdown-icon="none"')

                            ui.element("div").classes("mono-divider")

                            ui.label("actions").classes("mono-section-title")

                            with ui.element("div").classes("mono-grid"):
                                ui.button("setup", on_click=lambda: run_authority("setup")).classes("mono-btn").props('flat no-caps')
                                ui.button("open", on_click=lambda: run_authority("open")).classes("mono-btn").props('flat no-caps')
                                ui.button("close", on_click=lambda: run_authority("close")).classes("mono-btn").props('flat no-caps')
                                ui.button("decrypt", on_click=lambda: run_authority("decrypt")).classes("mono-btn").props('flat no-caps')

                            ui.button("tally results", on_click=lambda: run_authority("tally")).classes("w-full mono-btn mono-btn-primary mt-2").props('flat no-caps')

                        with ui.column().classes("flex-1 min-w-[280px]"):
                            ui.label("output").classes("mono-section-title")
                            authority_out = ui.textarea(placeholder="waiting for command...").classes("w-full mono-output").props('dark dense borderless readonly autogrow')

                    def run_authority(command: str) -> None:
                        try:
                            args = ["authority_client.py", command, "--node", node.value]
                            if command in {"setup", "decrypt"}:
                                args += ["--authority", authority_id.value]
                            authority_out.value = f"> {command}\n\n{run_cmd(args)}"
                            ui.notify(f"{command} complete", type="positive", position="bottom-right", timeout=2000)
                        except Exception as exc:
                            authority_out.value = f"> {command}\n\nerror: {str(exc)}"
                            ui.notify("command failed", type="negative", position="bottom-right", timeout=2000)

                # Voter panel
                with ui.tab_panel(voter_tab).classes("p-0 pt-8"):
                    with ui.row().classes("items-center mb-8"):
                        ui.html('<div class="mono-status"><div class="mono-status-dot"></div>awaiting vote</div>')

                    with ui.row().classes("w-full gap-8 flex-wrap"):
                        with ui.column().classes("flex-1 min-w-[280px]"):
                            ui.label("voter").classes("mono-section-title")

                            ui.label("node url").classes("mono-label")
                            node_v = ui.input(value="http://127.0.0.1:8001").classes("w-full mono-input mb-4").props('dark dense borderless')

                            ui.label("voter id").classes("mono-label")
                            voter_id = ui.input(value="alice").classes("w-full mono-input mb-4").props('dark dense borderless')

                            ui.element("div").classes("mono-divider")

                            ui.label("ballot").classes("mono-section-title")

                            ui.label("select candidate").classes("mono-label")
                            candidate = ui.select(
                                {0: "candidate a", 1: "candidate b"},
                                value=0
                            ).classes("w-full mono-input mb-4").props('dark dense borderless options-dark dropdown-icon="none"')

                            ui.label("your vote is encrypted end-to-end").classes("mono-hint mb-4")

                            ui.button("cast vote", on_click=lambda: cast_vote()).classes("w-full mono-btn mono-btn-primary").props('flat no-caps')

                        with ui.column().classes("flex-1 min-w-[280px]"):
                            ui.label("confirmation").classes("mono-section-title")
                            voter_out = ui.textarea(placeholder="vote receipt will appear here...").classes("w-full mono-output").props('dark dense borderless readonly autogrow')

                    def cast_vote() -> None:
                        try:
                            voter_out.value = f"> vote --candidate {candidate.value}\n\n" + run_cmd([
                                "voter_client.py",
                                "--voter-id", voter_id.value,
                                "--candidate", str(candidate.value),
                                "--node", node_v.value,
                            ])
                            ui.notify("vote recorded", type="positive", position="bottom-right", timeout=2000)
                        except Exception as exc:
                            voter_out.value = f"> vote\n\nerror: {str(exc)}"
                            ui.notify("vote failed", type="negative", position="bottom-right", timeout=2000)

        ui.element("div").classes("mono-divider mt-12")
        with ui.row().classes("w-full justify-between items-center"):
            ui.label("sayat serik, zhambyl maksotov, aslan onalbek").classes("mono-footer")

if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        title="open vote",
        favicon="",
        dark=True,
        reload=True,
    )
