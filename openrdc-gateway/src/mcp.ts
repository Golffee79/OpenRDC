// SPDX-License-Identifier: Apache-2.0
// MCP tools are a 1:1 thin mapping over the OpenRDC API. No provider logic.
// Tools are registered ONLY for host-granted capabilities (fail closed).
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { HostClient } from "./client.js";

export type Granted = Set<string>;

export function buildServer(host: HostClient, granted: Granted): McpServer {
  const server = new McpServer({ name: "openrdc", version: "0.1.0" });

  if (granted.has("screen.capture")) {
    server.tool(
      "openrdc_capture",
      "Capture the desktop screen. Returns frame_id + geometry + PNG image.",
      { monitor_id: z.string().optional(), max_width: z.number().int().min(320).max(3840).optional() },
      async ({ monitor_id, max_width }) => {
        const { status, json } = await host.call("/v1/screen/capture", { monitor_id, max_width });
        if (status !== 200) return err(json);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                frame_id: json.frame_id,
                monitor_id: json.monitor_id,
                source_width: json.source_width,
                source_height: json.source_height,
                output_width: json.output_width,
                output_height: json.output_height,
                scale: json.scale,
              }),
            },
            { type: "image" as const, data: json.image_base64, mimeType: "image/png" },
          ],
        };
      },
    );
  }

  if (granted.has("mouse.click")) {
    server.tool(
      "openrdc_click",
      "Click at frame-space coordinates from a prior openrdc_capture.",
      {
        frame_id: z.string().uuid(),
        x: z.number().int().min(0),
        y: z.number().int().min(0),
        button: z.enum(["left", "right", "middle"]).default("left"),
      },
      async ({ frame_id, x, y, button }) => {
        const { status, json } = await host.call("/v1/mouse/click", { frame_id, x, y, button });
        if (status !== 200) return err(json);
        return { content: [{ type: "text" as const, text: "ok" }] };
      },
    );
  }

  if (granted.has("keyboard.type")) {
    server.tool(
      "openrdc_type",
      "Type plain text (max 1024 chars).",
      { text: z.string().min(1).max(1024) },
      async ({ text }) => {
        const { status, json } = await host.call("/v1/keyboard/type", { text });
        if (status !== 200) return err(json);
        return { content: [{ type: "text" as const, text: "ok" }] };
      },
    );
  }

  if (granted.has("keyboard.press")) {
    server.tool(
      "openrdc_key",
      "Press a key with optional modifiers. Any modifiers need the dangerous capability on the host.",
      {
        key: z.string().min(1).max(32),
        modifiers: z.array(z.enum(["ctrl", "shift", "alt"])).default([]),
      },
      async ({ key, modifiers }) => {
        const { status, json } = await host.call("/v1/keyboard/press", { key, modifiers });
        if (status !== 200) return err(json);
        return { content: [{ type: "text" as const, text: "ok" }] };
      },
    );
  }

  return server;
}

function err(json: any) {
  const code = json?.error?.code ?? "internal";
  const message = json?.error?.message ?? "unknown error";
  return { content: [{ type: "text" as const, text: `${code}: ${message}` }], isError: true as const };
}
