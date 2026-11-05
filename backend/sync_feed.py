"""Run `python -m backend.sync_feed --once`, or omit --once for a local scheduler."""
import argparse
import asyncio
import json
from .services.openphish_service import OpenPhishService

async def run(once):
    service = OpenPhishService()
    while True:
        outcome = await service.sync_feed()
        print(json.dumps(outcome))
        if once or outcome['status'] in ('disabled', 'not_configured'):
            break
        await asyncio.sleep(max(43200, service.settings.feed_interval))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--once', action='store_true')
    asyncio.run(run(parser.parse_args().once))
