# main.py
import asyncio
from aiohttp import web
import json

from job1 import run_job as run_job1
from job2 import run_job as run_job2

routes = web.RouteTableDef()


@routes.post("/run-job")
async def handle_job(request):
    try:
        data = await request.json()

        job_id = data.get("jobId")
        job_payload = data.get("jobPayload", {})

        if not job_id:
            return web.json_response({"success": False, "error": "jobId is required"}, status=400)

        # Dispatch Jobs
        if job_id == 1:
            asyncio.create_task(run_job1(job_payload))
            return web.json_response({"success": True, "message": "Job 1 started"})

        elif job_id == 2:
            asyncio.create_task(run_job2(job_payload))
            return web.json_response({"success": True, "message": "Job 2 started"})

        else:
            return web.json_response({"success": False, "error": "Invalid jobId"}, status=400)

    except Exception as e:
        return web.json_response({"success": False, "error": str(e)}, status=500)


async def init_app():
    app = web.Application()
    app.add_routes(routes)
    return app


if __name__ == "__main__":
    web.run_app(init_app(), port=8000)
