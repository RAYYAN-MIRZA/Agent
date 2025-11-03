import json
import asyncio
from signalrcore.hub_connection_builder import HubConnectionBuilder

BACKEND_URL = "https://192.168.100.34:7079/agentHub"  # SignalR hub
AGENT_ID = "AGENT_001"


class AsyncAgentClient:
    def __init__(self):
        # Create SignalR hub connection
        self.hub = (
            HubConnectionBuilder()
            .with_url(BACKEND_URL, options={"verify_ssl": False})
            .build()
        )

        # Connection events
        self.hub.on_open(self.on_open)
        self.hub.on_close(self.on_close)
        self.hub.on_error(self.on_error)

        # Backend → Agent handlers
        self.hub.on("TriggerScan", self.on_trigger_scan)
        self.hub.on("PingAgent", self.on_ping_agent)

    # --- Connection lifecycle ---
    def on_open(self):
        print("✅ Connected to backend SignalR Hub")

    def on_close(self):
        print("🔌 Connection closed")

    def on_error(self, error):
        print("❌ SignalR error:", error)

    # --- Backend → Agent ---
    def on_trigger_scan(self, args):
        print("📡 Backend requested scan:",args)
        
        # Trigger your actual scan logic here          fl;kglfdkglfdkgl;dfkgl;fdkg; ok
        
        
        # asyncio.create_task(self.send_scan_result({
        #     "agent_id": AGENT_ID,
        #     "type": "scan_result",
        #     "health": {"devices_found": 3, "triggered_by": "backend"}
        # }))

    def on_ping_agent(self, args):
        print("🏓 Ping received from backend:", args)
        asyncio.create_task(self.send_scan_result({
            "agent_id": AGENT_ID,
            "pong": True,
            "time": asyncio.get_event_loop().time()
        }))

    # --- Agent → Backend ---
    async def send_scan_result(self, payload):
        try:
            self.hub.send("SendScanResult", [json.dumps(payload)])
            print("🚀 Sent payload to backend:")
        except Exception as e:
            print("⚠️ Failed to send payload:", e)

    # --- Run client ---
    async def run(self):
        # Start hub connection
        self.hub.start()
        print("🟢 AsyncAgent running...")
        try:
            while True:
                await asyncio.sleep(1)  # keep loop alive, non-blocking
        finally:
            self.hub.stop()


if __name__ == "__main__":
    client = AsyncAgentClient()
    asyncio.run(client.run())
