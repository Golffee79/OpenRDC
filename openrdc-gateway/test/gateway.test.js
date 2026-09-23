// SPDX-License-Identifier: Apache-2.0
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { HostClient } from "../dist/client.js";
import { buildServer } from "../dist/mcp.js";

let baseUrl;
let server;
let lastAuth = "";
const routes = {
  "/v1/screen/capture": () => ({
    status: 200,
    body: {
      frame_id: "11111111-1111-1111-1111-111111111111",
      monitor_id: "m0",
      source_width: 800,
      source_height: 600,
      output_width: 400,
      output_height: 300,
      scale: 0.5,
      image_base64: Buffer.from([137, 80, 78, 71]).toString("base64"),
      mime: "image/png",
    },
  }),
  "/v1/mouse/click": () => ({ status: 200, body: { ok: true } }),
  "/v1/keyboard/type": () => ({ status: 200, body: { ok: true } }),
  "/v1/keyboard/press": () => ({
    status: 403,
    body: { error: { code: "forbidden_capability", message: "no", retryable: false, request_id: "r" } },
  }),
};

before(async () => {
  server = createServer((req, res) => {
    lastAuth = req.headers.authorization ?? "";
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const fn = routes[req.url];
      const out = fn ? fn() : { status: 404, body: {} };
      res.writeHead(out.status, { "content-type": "application/json" });
      res.end(JSON.stringify(out.body));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

async function toolsOf(granted) {
  const host = new HostClient({ baseUrl, token: "tok123" });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const mcpServer = buildServer(host, new Set(granted));
  const client = new Client({ name: "t", version: "0" });
  await Promise.all([mcpServer.connect(st), client.connect(ct)]);
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name).sort();
  await client.close();
  await mcpServer.close();
  return { client: null, names, host };
}

test("client sends bearer token", async () => {
  const c = new HostClient({ baseUrl, token: "tok123" });
  const { status } = await c.call("/v1/mouse/click", { frame_id: "x", x: 1, y: 1 });
  assert.equal(status, 200);
  assert.equal(lastAuth, "Bearer tok123");
});

test("full grants expose 4 tools; capture returns geometry + image; press maps forbidden", async () => {
  const host = new HostClient({ baseUrl, token: "tok123" });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const mcpServer = buildServer(
    host,
    new Set(["screen.capture", "mouse.click", "keyboard.type", "keyboard.press"]),
  );
  const client = new Client({ name: "t", version: "0" });
  await Promise.all([mcpServer.connect(st), client.connect(ct)]);
  const { tools } = await client.listTools();
  assert.deepEqual(
    tools.map((t) => t.name).sort(),
    ["openrdc_capture", "openrdc_click", "openrdc_key", "openrdc_type"],
  );
  const cap = await client.callTool({ name: "openrdc_capture", arguments: {} });
  const text = JSON.parse(cap.content[0].text);
  assert.equal(text.frame_id, "11111111-1111-1111-1111-111111111111");
  assert.equal(text.scale, 0.5);
  assert.equal(cap.content[1].type, "image");
  const press = await client.callTool({ name: "openrdc_key", arguments: { key: "F4", modifiers: ["alt"] } });
  assert.equal(press.isError, true);
  assert.match(press.content[0].text, /forbidden_capability/);
  await client.close();
  await mcpServer.close();
});

test("capability filtering hides ungranted tools", async () => {
  const { names } = await toolsOf(["screen.capture"]);
  assert.deepEqual(names, ["openrdc_capture"]);
  // Zero grants: server exposes no tools at all (tools/list unsupported).
  const host = new HostClient({ baseUrl, token: "tok123" });
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const mcpServer = buildServer(host, new Set());
  const client = new Client({ name: "t", version: "0" });
  await Promise.all([mcpServer.connect(st), client.connect(ct)]);
  await assert.rejects(() => client.listTools(), /Method not found/);
  await client.close();
  await mcpServer.close();
});
