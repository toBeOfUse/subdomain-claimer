import sys
import asyncio
from pathlib import Path
from validators.domain import domain
from mitmproxy import http
from minotaur import Inotify, Mask


if len(sys.argv) != 2:
    print("need path to watch")
    exit()
path = sys.argv[1]

logpath = Path(path) / "log.txt"

MAIN_DOMAIN = "simpsr.us"

domains_to_ports = {}

def scan():
    domains_to_ports = {}
    logfile = open(logpath)
    for sfilepath in Path(path).glob("*"):
        sfile = open(sfilepath)
        try:
            full_domain = f"{sfilepath.name}.{MAIN_DOMAIN}"
            if not domain(full_domain):
                logfile.write(f"error processing {sfilepath}: ")
                logfile.write(f"{full_domain} does not seem to be a valid domain name\n")
            else:
                port = int(sfile.read().strip())
                if not (1024 <= port <= 65535):
                    logfile.write(f"error processing {sfilepath}: ")
                    logfile.write(f"port number {port} is outside of the valid "
                                    "range (1024-65535)\n")
                else:
                    logfile.write(f"mapping {full_domain} to port {port}\n")
                    domains_to_ports[full_domain] = port
        except:
            logfile.write(f"could not parse port from {sfilepath}; "
                            "does the file contain a single integer?\n")
        sfile.close()
    logfile.close()


async def watch_files():
    with Inotify(blocking=False) as n:
        n.add_watch('.', Mask.CREATE | Mask.DELETE | Mask.MOVE)
        async for evt in n:
            print(evt)
            scan()

asyncio.get_event_loop().create_task(watch_files())

async def request(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_host in domains_to_ports:
        flow.request.host = "127.0.0.1"
        flow.request.port = domains_to_ports[flow.request.pretty_host]
    print(flow)
