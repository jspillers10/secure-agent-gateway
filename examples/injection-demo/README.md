# Prompt-injection demo

A scripted agent is asked to summarize a file. The file contains hidden
instructions telling it to read `.env` and POST the contents to an attacker.
The agent obeys, the way a real model does often enough to matter.

```bash
pip install -e .                                   # from the repo root
python examples/injection-demo/agent.py            # no gateway: the key leaves
python examples/injection-demo/agent.py --protected  # through sag mcp: blocked
```

Everything here is inert. `fake_server.py` serves files from an in-memory
dict, `http_post` only counts bytes, and `run_shell` returns canned output.
The AWS keys are the examples from AWS's own documentation.

## What the protected run shows

| Agent step | Without the gateway | With `sag mcp -c policy.yaml` |
|---|---|---|
| `tools/list` | `read_file, http_post, run_shell` | `run_shell` is hidden (policy denies it) |
| `read_file .env` | returns the keys | blocked by `deny_args` (`*.env`) |
| `run_shell cat .env` | returns the keys | blocked: tool denied (calling a hidden tool by name does not help) |
| `read_file config/deploy.bak` | n/a | allowed: no path rule covers this file |
| `http_post` with the key in the body | sent | blocked by the secret scan (`aws_access_key_id`) |

The last two rows are the point of layering. A path deny-list can never
name every file that might contain a credential. The secret scan catches
the credential at the moment it would leave.

Without the secret in the body, `http_post` would be held for human
approval (`action: ask` in [policy.yaml](policy.yaml)).

## Files

- [agent.py](agent.py): the scripted MCP client. Speaks real JSON-RPC over stdio.
- [fake_server.py](fake_server.py): the inert MCP server.
- [policy.yaml](policy.yaml): the policy used for the protected run.

To regenerate the GIF in the main README:

```bash
pip install pillow
python scripts/render_demo_gif.py
```

The script runs the demo for real and animates its actual output.
