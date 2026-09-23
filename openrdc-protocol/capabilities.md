# Capabilities

Flat hierarchical namespace, exact-string matching, default-deny, no inheritance.

- `screen.capture`
- `mouse.click`
- `keyboard.type`
- `keyboard.press`
- `keyboard.press.dangerous`

Granting `keyboard.press` does NOT grant `keyboard.press.dangerous`.
M0 rule: any `keyboard.press` request with a non-empty `modifiers` array
requires BOTH `keyboard.press` AND `keyboard.press.dangerous`.
Modifier-free keys need only `keyboard.press`.
No wildcards in M0. Unknown capabilities in config are rejected at startup.
The gateway exposes MCP tools only for granted capabilities (fail closed).
