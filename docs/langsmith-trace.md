# Capturing a LangSmith trace

A trace is the strongest evidence a submission can carry for "agent reasoning
and architecture depth", because it is not a claim about the architecture, it is
a recording of it: the orchestrator fanning out to several specialists at once,
each agent's prompt and response, and the wall time of every step.

Everything needed is already wired. Tracing is off by default because it sends
prompt and response content to a third party, and this project analyses hostile
material.

## Before you start

Both are already true on this machine, but check if you are somewhere else:

```bash
.venv/bin/python -c "import langsmith, langchain_groq; print('ok')"
```

`langchain_groq` matters. The LLM layer falls back to raw HTTP when a LangChain
provider package is missing, **and LangSmith cannot see those calls** — you would
get a trace of the graph with no model steps in it. `make verify` reports which
path your LLM calls actually take.

## 1. Get a key

<https://smith.langchain.com> → Settings → API keys → create one.

## 2. Turn it on

Three lines in `.env`:

```bash
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=<paste your key>
LANGCHAIN_PROJECT=threatiq-capstone
```

A distinct project name is worth it: the trace you screenshot should not be
sitting in a list beside twenty experiments.

`setup_langsmith` exports these into the process environment at API start-up, so
**the API must be restarted** for them to take effect. If it is running with
`--reload`, editing `.env` is enough; otherwise restart it yourself.

## 3. Make sure a model is actually configured

A trace is only interesting if the agents reached a model. Confirm:

```bash
curl -s localhost:8000/health | .venv/bin/python -c \
  "import json,sys; d=json.load(sys.stdin); print(d['llm'])"
```

You want `{'enabled': True, 'provider': 'groq', 'model': 'openai/gpt-oss-120b'}`.
If `enabled` is false, set `GROQ_API_KEY` in `.env` first.

## 4. Run the investigation worth tracing

The phishing email is the one to use. It exercises the most agents, and the
injected instruction in the body makes the trace itself interesting: you can
open the orchestrator's prompt and see the attacker's sentence sitting inside a
fenced block, defanged, being ignored.

```bash
K=$(grep -E '^API_KEY=' .env | cut -d= -f2-)
curl -s -X POST localhost:8000/investigate \
  -H 'Content-Type: application/json' -H "X-API-Key: $K" \
  -d @docs/trace-sample.json | .venv/bin/python -c \
  "import json,sys; d=json.load(sys.stdin); print(d['label'], d['risk']['score'])"
```

## 5. Screenshot the right view

In LangSmith, open the project and then the run named
`threatiq-investigation-<id>` — `service.py` sets that `run_name`, along with
metadata carrying the investigation id, the input kind and the graph backend.

Capture the **trace tree**, not a single span. What a marker should be able to
see in one image:

- `orchestrator` at the top
- several specialist agents at the **same indent level**, which is what shows
  they ran in parallel rather than in sequence
- `correlation`, `risk`, `compliance`, `remediation`, `report` in order beneath
- latency against each one

Save it as `screenshots/03-langsmith-trace.png` and reference it from the README
under **Architecture**, with a caption naming what it proves:

```markdown
![A LangSmith trace of one investigation: the orchestrator fans out to three
specialist agents in parallel, which converge on correlation before the
deterministic risk engine runs](screenshots/03-langsmith-trace.png)
```

## 6. Turn it back off

```bash
LANGCHAIN_TRACING_V2=false
```

Leaving it on ships every prompt, including quoted attacker-controlled text, to
a third party for as long as the deployment runs. Fine for one captured run,
not something to leave enabled on a public deployment.

Do **not** put `LANGCHAIN_API_KEY` in the Streamlit Cloud secrets. That key is
not in `OVERRIDABLE_SETTINGS`, so a visitor could not supply one anyway, and a
public deployment tracing every stranger's investigation into your account is
both a bill and a privacy problem.
