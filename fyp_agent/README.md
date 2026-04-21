# FYP Agent

Python client that runs on a Kali (or any Linux) box and executes scans
dispatched by the FYP backend over SignalR.

## Install

```bash
cd Agent
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -r fyp_agent/requirements.txt
```

## Bootstrap

1. On the backend, mint an enrollment token (24h TTL):

   ```bash
   curl -X POST http://localhost:5000/api/v1/agents/enrollments \
        -H 'Content-Type: application/json' \
        -d '{"label":"kali-lab","ttlHours":24}'
   ```

   The response contains `enrollmentToken`. Save it somewhere safe — the
   server only ever hands it back once.

2. Copy the sample config and paste the token:

   ```bash
   mkdir -p ~/.fyp-agent
   cp fyp_agent/config.sample.yaml ~/.fyp-agent/config.yaml
   $EDITOR ~/.fyp-agent/config.yaml
   ```

   Or pass everything via env vars:

   ```bash
   export FYP_AGENT_API_BASE_URL=http://localhost:5000
   export FYP_AGENT_ENROLLMENT_TOKEN=<token>
   export FYP_AGENT_NAME=kali-lab
   ```

## Run

```bash
python -m fyp_agent
```

On first run the agent exchanges the enrollment token for long-lived
credentials and stores them in `~/.fyp-agent/state.json`. Subsequent
runs skip enrollment entirely.

## What it does

- Connects to `/hubs/agent` over SignalR using its agent token.
- Reports `Heartbeat` every `heartbeatIntervalSeconds`.
- On each `Dispatch` event:
  1. Creates a per-run workdir at `~/.fyp-agent/artifacts/<run-id>/`.
  2. Expands the `$ARTIFACT_DIR` placeholder in argv to that path.
  3. Spawns the executable, streams stdout/stderr back over `RunOutput`.
  4. On exit, picks the primary output file (prefers `*.xml` for nmap),
     requests a presigned PUT ticket from
     `POST /api/v1/runs/{runId}/artifacts/ticket`, uploads directly to
     MinIO, and reports the resulting `s3://…` URI on `RunCompleted`.
- The backend's worker then consumes the artifact from the
  `fyp:ingest:default` Redis stream, parses the XML, and upserts
  `Assets` and `Findings`.

Upload failures are non-fatal: the run still completes, just with a
null `artifactUri`. Check the agent log for the underlying error.
