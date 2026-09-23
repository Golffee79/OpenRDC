// SPDX-License-Identifier: Apache-2.0
// E2E driver: speaks MCP JSON-RPC over stdio to a real gateway, which talks
// to a real host. No mocks. Exits 0 iff the full vertical slice works:
// capture -> click(frame_id) -> type -> key(Enter).
import { spawn } from "node:child_process";

const gw = spawn("node", ["dist/index.js"], {
  cwd: new URL("..", import.meta.url).pathname,
  stdio: ["pipe", "pipe", "inherit"],
  env: process.env,
});

let buf = "";
let nextId = 1;
const pending = new Map();
gw.stdout.on("data", (c) => {
  buf += c.toString();
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(JSON.stringify(msg.error)));
      else resolve(msg.result);
    }
  }
});

function req(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    gw.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}
function notify(method) {
  gw.stdin.write(JSON.stringify({ jsonrpc: "2.0", method }) + "\n");
}
const ok = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"} mcp ${name} ${extra}`);
  if (!cond) process.exitCode = 1;
};

await req("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "e2e", version: "0" },
});
notify("notifications/initialized");

const { tools } = await req("tools/list", {});
const names = tools.map((t) => t.name).sort();
ok("tools/list", JSON.stringify(names) === JSON.stringify(["openrdc_capture", "openrdc_click", "openrdc_key", "openrdc_type"]), names.join(","));

const cap = await req("tools/call", { name: "openrdc_capture", arguments: {} });
const geo = JSON.parse(cap.content[0].text);
ok("capture", !!geo.frame_id && cap.content[1].type === "image", `frame=${geo.frame_id} ${geo.output_width}x${geo.output_height}`);

const click = await req("tools/call", {
  name: "openrdc_click",
  arguments: { frame_id: geo.frame_id, x: 10, y: 10, button: "left" },
});
ok("click", click.content[0].text === "ok" && !click.isError);

const typeR = await req("tools/call", {
  name: "openrdc_type",
  arguments: { text: "E2E-SECRET-TYPED-TEXT via-mcp" },
});
ok("type", typeR.content[0].text === "ok" && !typeR.isError);

const key = await req("tools/call", {
  name: "openrdc_key",
  arguments: { key: "Enter", modifiers: [] },
});
ok("key", key.content[0].text === "ok" && !key.isError);

gw.kill();
process.exit(process.exitCode ?? 0);
