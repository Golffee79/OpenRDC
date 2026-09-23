// SPDX-License-Identifier: Apache-2.0
// Thin client for the provider-neutral OpenRDC API. No desktop access here.
import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface HostClientOpts {
  baseUrl: string;
  token?: string;
}

export function defaultTokenPath(): string {
  if (process.env.OPENRDC_TOKEN_FILE) return process.env.OPENRDC_TOKEN_FILE;
  const base =
    process.env.XDG_CONFIG_HOME ?? join(process.env.HOME ?? "/tmp", ".config");
  return join(base, "openrdc", "token");
}

export class HostClient {
  constructor(private opts: HostClientOpts) {}
  private token(): string {
    if (this.opts.token) return this.opts.token;
    if (process.env.OPENRDC_TOKEN) return process.env.OPENRDC_TOKEN;
    return readFileSync(defaultTokenPath(), "utf8").trim();
  }
  async call(path: string, body?: unknown): Promise<{ status: number; json: any }> {
    const res = await fetch(`${this.opts.baseUrl}${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${this.token()}`,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    return { status: res.status, json };
  }
}
