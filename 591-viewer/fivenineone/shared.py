import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Self

import curl_cffi
from genutility.cache import cache
from playwright._impl._console_message import ConsoleMessage
from playwright._impl._errors import Error
from playwright._impl._frame import Frame
from playwright.sync_api import sync_playwright
from playwright_stealth import Stealth

logger = logging.getLogger(__name__)

IMPERSONATE = "chrome"


def read_communities(path: Path) -> Iterator[dict]:
    with path.open(encoding="utf-8") as fr:
        items = json.load(fr)

    for item in items:
        if "data" not in item:
            continue

        yield {
            "rent_id": item["rent_id"],
            "address": item["data"]["address"],
            "price": item["data"]["rent_data"]["price_min"]["price"],
        }


@cache(Path("get_rent_community"), serializer="json")
def get_rent_community(rent_id: int) -> dict:
    url = "https://bff-house.591.com.tw/v1/rent/community"
    r = curl_cffi.get(url, params={"rent_id": rent_id}, impersonate=IMPERSONATE)
    return r.json()


class FiveNineOneBrowser:
    def __init__(self, headless: bool = True) -> None:
        self.url_tpl = "https://rent.591.com.tw/{rent_id}"
        self.cm = Stealth().use_sync(sync_playwright())
        self.p = self.cm.__enter__()

        with open("spoof_shadow_root.js", encoding="utf-8") as fr:
            self.js_attach_shadow = fr.read()

        with open("devtools_chrome-itzzzme.js", encoding="utf-8") as fr:
            self.js_block_devtool = fr.read()

        self.browser = self.p.webkit.launch(headless=headless)

    def on_console(self, msg: ConsoleMessage) -> None:
        m = re.search(
            r"^(Blocked resize event listener|Blocked setTimeout with delay \d+ms|Blocked setInterval with delay \d+ms)$",
            msg.text,
        )
        if m is None:
            logger.warning("[%s] %s", msg.type, msg.text)

    def on_page_error(self, e: Error) -> None:
        logger.warning("%s\n%s", e.message, e.stack)

    def on_frame_navigated(self, frame: Frame) -> None:
        logger.info("Frame navigated to: %s from %s", frame.url, frame.page.main_frame)

    def close(self):
        self.cm.__exit__(None, None, None)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args):
        self.close()

    @cache(Path("get_obfuscated_html"), serializer="msgpack", ignore_first_arg=True, return_cached=True)
    def get_obfuscated_html(self, rent_id: int) -> dict:
        url = self.url_tpl.format(rent_id=rent_id)

        page = self.browser.new_page()

        page.add_init_script(self.js_attach_shadow)
        page.add_init_script(self.js_block_devtool)

        page.on("console", self.on_console)
        page.on("framenavigated", self.on_frame_navigated)
        page.on("pageerror", self.on_page_error)

        page.goto(url)

        shadow_address = """() => {
            const el = document.querySelector('span.load-map wc-obfuscate-rent-map-address');
            if (!el) return false;
            if (!el.shadowRoot) return false;
            return true;
        }"""

        page.wait_for_function(shadow_address, timeout=10_000)
        page.wait_for_timeout(1_000)

        address_node_shadow_html = page.eval_on_selector(
            "span.load-map wc-obfuscate-rent-map-address", "el => el.shadowRoot.innerHTML"
        )
        price_node_shadow_html = page.eval_on_selector(
            "span.c-price wc-obfuscate-c-price", "el => el.shadowRoot.innerHTML"
        )
        area_node_shadow_html = page.eval_on_selector(
            "div.pattern wc-obfuscate-c-area", "el => el.shadowRoot.innerHTML"
        )
        floor_node_shadow_html = page.eval_on_selector(
            "div.pattern wc-obfuscate-c-floor", "el => el.shadowRoot.innerHTML"
        )

        return {
            "address": address_node_shadow_html,
            "price": price_node_shadow_html,
            "area": area_node_shadow_html,
            "floor": floor_node_shadow_html,
        }

    @cache(Path("parse_obfuscated"), serializer="json", ignore_first_arg=True, return_cached=True)
    def parse_obfuscated(self, html: str) -> list[dict[str, str]]:
        page = self.browser.new_page()
        page.set_content(html)

        styles = page.eval_on_selector_all(
            "span i",
            """
        els => els.map(el => {
          const style = getComputedStyle(el);
          return {
            text: el.textContent,
            display: style.display,
            position: style.position,
            width: style.width,
            height: style.height,
            left: style.left,
            overflow: style.overflow,
          };
        })
        """,
        )

        return styles

    def deobfuscate_html(self, styles: list[dict[str, str]]) -> str:
        styles = [
            style
            for style in styles
            if (style["display"] != "none" and style["width"] != "0px" and style["position"] != "fixed")
        ]
        styles = sorted(styles, key=lambda style: float(style["left"][:-2]))
        return "".join(style["text"] for style in styles)

    def extract(self, rent_id: int) -> tuple[bool, dict[str, Any]]:
        cached, htmls = self.get_obfuscated_html(rent_id)
        out = {}
        for name, html in htmls.items():
            _, item = self.parse_obfuscated(html)
            item_str = self.deobfuscate_html(item)
            out[name] = item_str
        return cached, out
