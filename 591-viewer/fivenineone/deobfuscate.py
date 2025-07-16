import json
import time
from argparse import ArgumentParser
from pathlib import Path

from genutility.rich import Progress
from playwright._impl._errors import TargetClosedError
from playwright._impl._errors import TimeoutError as PlayweightTimeoutError
from rich.progress import Progress as RichProgress

from .shared import FiveNineOneBrowser, read_communities


def read_infos(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fr:
        return json.load(fr)


def main():
    parser = ArgumentParser()
    parser.add_argument("--delay", type=float, default=10)
    args = parser.parse_args()

    addresses = {item["rent_id"]: item["address"] for item in read_communities(Path("communities.json"))}
    addresses = {item["rent_id"]: None for item in read_infos(Path("infos.json"))}

    try:
        with FiveNineOneBrowser() as fno, RichProgress() as p:
            progress = Progress(p)
            for rent_id, address in progress.track(addresses.items()):
                cached, extraced = fno.extract(rent_id)
                print(rent_id, address == extraced["address"], address, extraced)
                if not cached:
                    time.sleep(args.delay)

    except TargetClosedError:
        print("browser closed")
    except PlayweightTimeoutError:
        print("playwright timeout")


if __name__ == "__main__":
    main()
