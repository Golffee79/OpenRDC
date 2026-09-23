// SPDX-License-Identifier: Apache-2.0
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { HostClient } from "./client.js";
import { buildServer } from "./mcp.js";

const baseUrl = process.env.OPENRDC_HOST ?? "http://127.0.0.1:18789";
const host = new HostClient({ baseUrl });

// Fail closed: only expose tools the host actually granted.
let granted: Set<string>;
try {
  const { status, json } = await host.call("/v1/system", undefined);
  if (status !== 200 || !Array.isArray(json?.granted)) {
    throw new Error(`system discovery failed: status=${status}`);
  }
  granted = new Set(json.granted);
} catch (e) {
  console.error(`openrdc-gateway: refusing to start: ${e}`);
  process.exit(1);
}

const server = buildServer(host, granted);
await server.connect(new StdioServerTransport());
