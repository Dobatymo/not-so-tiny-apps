import json
import logging
import time
from argparse import ArgumentParser
from collections.abc import Set
from pathlib import Path
from urllib.parse import urlsplit

import curl_cffi
from bs4 import BeautifulSoup
from genutility.rich import Progress
from rich.progress import Progress as RichProgress

from .data import Layout, Region, Section, region_sections, translations_en
from .shared import IMPERSONATE, get_rent_community

logger = logging.getLogger(__name__)


def dl_query_page(
    region: Region, sections: Set[Section], layouts: Set[Layout], page: int
) -> tuple[str, dict, str, bytes]:
    if sections - region_sections[region]:
        raise ValueError("Unsupported sections for this region")

    params = {
        "region_p": str(region.value),
        "section_p": ",".join(str(i.value) for i in sections),
        "layout_p": ",".join(str(i.value) for i in layouts),
        "page_p": str(page),
    }

    url_tpl = (
        "https://rent.591.com.tw/list?kind=1&region={region_p}&section={section_p}&layout={layout_p}&page={page_p}"
    )

    url = url_tpl.format_map(params)

    r = curl_cffi.get(url, impersonate=IMPERSONATE)
    r.raise_for_status()
    return url, params, r.encoding, r.content


def dl_query(region: Region, section: Section, layout: Layout, max_page: int, delay: float) -> None:
    for page in range(1, max_page):
        print(f"Downloading page {page}")
        url, params, encoding, content = dl_query_page(region, {section}, {layout}, page)

        filename = Path("{region_p}-{section_p}-{layout_p}-{page_p}.html".format_map(params))
        filename_pretty = Path("{region_p}-{section_p}-{layout_p}-{page_p}.pretty.html".format_map(params))

        with filename.open("wb") as fw:
            fw.write(content)

        with filename_pretty.open("w", encoding="utf-8") as fw:
            soup = BeautifulSoup(content, features="html5lib", from_encoding=encoding)
            fw.write(soup.prettify())

        time.sleep(delay)


def parse(region: Region, section: Section, layout: Layout, max_page: int) -> None:
    infos: list[dict] = []

    for page in range(1, max_page):
        with open(f"{region.value}-{section.value}-{layout.value}-{page}.html", encoding="utf-8") as fr:
            soup = BeautifulSoup(fr, features="html5lib")

        item_infos = soup.find_all("div", class_="item-info-title")
        for item in item_infos:
            info = {"url": urlsplit(item.a["href"]), "title": item.a["title"]}
            info["rent_id"] = int(info["url"].path[1:])
            infos.append(info)

    with Path("infos.json").open("w", encoding="utf-8") as fw:
        json.dump(infos, fw)


def download_communities(delay: float) -> None:
    with Path("infos.json").open(encoding="utf-8") as fr:
        infos = json.load(fr)

    rent_communities: list[dict] = []

    with RichProgress() as p:
        progress = Progress(p)
        for info in progress.track(infos):
            rent_id = info["rent_id"]
            try:
                print("Downloading rent community", rent_id)
                d = get_rent_community(rent_id)
            except KeyboardInterrupt:
                print("interrupted")
                break
            assert "rent_id" not in d
            d["rent_id"] = rent_id
            rent_communities.append(d)
            time.sleep(delay)

    with Path("communities.json").open("w", encoding="utf-8") as fw:
        json.dump(rent_communities, fw)


def main():
    all_regions = {translations_en[region]: region for region in Region}
    all_sections = {translations_en[section]: section for section in Section}
    all_layouts = {translations_en[layout]: layout for layout in Layout}

    parser = ArgumentParser()
    parser.add_argument("action", choices=("download", "parse", "download-communities"))
    parser.add_argument("--region", choices=all_regions, required=True)
    parser.add_argument("--section", choices=all_sections, required=True)
    parser.add_argument("--layout", choices=all_layouts, required=True)
    parser.add_argument("--max-page", type=int, required=True)
    parser.add_argument("--delay", type=float, default=10)
    args = parser.parse_args()

    region = all_regions[args.region]
    section = all_sections[args.section]
    layout = all_layouts[args.layout]

    if args.action == "download":
        dl_query(region, section, layout, args.max_page, args.delay)
    elif args.action == "parse":
        parse(region, section, layout, args.max_page)
    elif args.action == "download-communities":
        download_communities(args.delay)
    else:
        assert False


if __name__ == "__main__":
    main()
