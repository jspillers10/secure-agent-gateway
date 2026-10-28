"""MCP stdio proxy: policy-enforced `tools/call` for any stdio MCP server.

`sag mcp -c policy.yaml -- <upstream command>` sits between an MCP client
and an upstream server, evaluates every `tools/call` against a YAML
policy, and forwards only allowed calls. See docs/mcp-proxy.md.
"""
