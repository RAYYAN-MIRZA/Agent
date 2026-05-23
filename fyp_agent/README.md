# FYP Agent

Python client for a **Kali or Linux** scan box. It connects to **FYP.Backend**, receives work over SignalR, runs tools (for example **nmap**), streams logs, and uploads artifacts to MinIO using presigned URLs from the API.

## Install

```bash
cd Agent
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -r fyp_agent/requirements.txt
```

## Bootstrap

1. Start **FYP.Backend** (default URL below uses port **5017** — same as `launchSettings.json` in the API project).

   Mint a one-time enrollment token:

   ```bash
   curl -X POST http://localhost:5017/api/v1/agents/enrollments \
        -H 'Content-Type: application/json' \
        -d '{"label":"kali-lab","ttlHours":24}'
   ```

   The JSON response includes **`enrollmentToken`**. Save it; the server does not show it again.

2. Copy the sample config and paste the token:

   ```bash
   mkdir -p ~/.fyp-agent
   cp fyp_agent/config.sample.yaml ~/.fyp-agent/config.yaml
   $EDITOR ~/.fyp-agent/config.yaml
   ```

   Or use environment variables:

   ```bash
   export FYP_AGENT_API_BASE_URL=http://localhost:5017
   export FYP_AGENT_ENROLLMENT_TOKEN=<token>
   export FYP_AGENT_NAME=kali-lab
   ```

   **`api_base_url`** must match where the API is reachable from this machine (no trailing path like `/api`).

## Run

```bash
python -m fyp_agent
```

First run exchanges the enrollment token for long-lived credentials and writes **`~/.fyp-agent/state.json`**. Later runs reuse that file.

## What it does

- Connects to **`/hubs/agent`** with the agent token.
- Sends **`Heartbeat`** on the interval from config.
- On **`Dispatch`**:
  1. Work directory under **`~/.fyp-agent/artifacts/<run-id>/`**
  2. Replaces **`$ARTIFACT_DIR`** in the argv template
  3. Runs the process; streams stdout/stderr as **`RunOutput`**
  4. After exit, prefers **`*.xml`** (nmap), requests **`POST /api/v1/runs/{runId}/artifacts/ticket`**, uploads to storage, sends **`RunCompleted`** with the artifact URI (for example `s3://…`)
- The worker consumes ingest from the Redis stream **`fyp:ingest:default`**, parses supported outputs, and updates **assets** and **findings**.

If upload fails, the run can still finish with a null **`artifactUri`**; check agent logs.

## Metasploit (lab)

When the agent runs inside **fyp-testing-lab1** with `agent-msf.Dockerfile`, reverse payloads must use the agent’s **lab-net IP** as `LHOST` (default `172.28.0.2`), not `127.0.0.1`. See **`fyp-testing-lab1/docs/MSF_LAB_NETWORKING.md`** and run **`scripts/msf-lab-smoke.sh`** after the stack is up.

## Related

- **FYP.Backend** — API and hubs
- **fyp-testing-lab1** — full Docker stack with an auto-enrolled agent
