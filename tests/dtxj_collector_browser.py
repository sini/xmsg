#!/usr/bin/env python3
"""Inspect a real collector CLI fixture in Chromium, including a CSP bypass control."""

import argparse
import http.server
import json
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--chromium", required=True)
    args = parser.parse_args()
    html = (args.fixture_dir / "page.html").read_bytes()
    headers = json.loads((args.fixture_dir / "headers.json").read_text())
    expected = json.loads((args.fixture_dir / "expect.json").read_text())

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = html
            if self.path == "/dom-positive":
                body = b"<html><body><img src='/resource-positive'><script>void 0</script></body></html>"
            elif self.path == "/network-positive":
                body = b"<html><body><img src='https://attacker.invalid/positive'></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"

    def inspect(page):
        assert page.locator("script, img, image, iframe, object, embed, link").count() == 0, (
            "hostile label added DOM resource or executable nodes"
        )
        assert page.locator("svg.endpoint").count() == expected["endpoints"], "endpoint DOM count changed"
        assert page.locator("article.event").count() == expected["events"], "event DOM count changed"
        assert page.locator("svg.lane").count() == expected["events"], "reported lane DOM count changed"
        assert page.locator(".endpoint-label").first.text_content().startswith(expected["label"])
        assert expected["label"] in page.locator("svg.endpoint").first.text_content(), "SVG label was not literal text"
        assert expected["label"] in page.locator("svg.lane").first.text_content(), "SVG lane was not literal text"
        assert page.locator("meta[http-equiv=refresh]").get_attribute("content") == "5"

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=args.chromium, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
            )
            try:
                total_requests = 0
                mode_failures = []
                unexpected_requests = 0
                for bypass in (False, True):
                    context = browser.new_context(bypass_csp=bypass)
                    requests = []

                    def route(request_route):
                        resource = request_route.request.url
                        requests.append(resource)
                        if resource.startswith(origin + "/"):
                            request_route.continue_()
                        else:
                            request_route.abort()

                    context.route("**/*", route)
                    page = context.new_page()
                    response = page.goto(origin + "/", wait_until="networkidle")
                    assert response.status == 200
                    for key, value in headers.items():
                        assert response.headers[key] == value, f"response header changed: {key}"
                    try:
                        inspect(page)
                    except AssertionError as error:
                        mode_failures.append(f"bypass={bypass}: {error}")
                    unexpected = [resource for resource in requests if resource not in (origin + "/", origin + "/favicon.ico")]
                    unexpected_requests += len(unexpected)
                    if unexpected:
                        mode_failures.append(f"bypass={bypass}: hostile label attempted a resource request")
                    total_requests += len(requests)
                    if bypass:
                        page.goto(origin + "/dom-positive", wait_until="networkidle")
                        try:
                            inspect(page)
                        except AssertionError as error:
                            assert "added DOM" in str(error), "DOM positive control failed for an unrelated predicate"
                        else:
                            raise AssertionError("DOM injection positive control was not detected")
                        requests.clear()
                        page.goto(origin + "/network-positive", wait_until="networkidle")
                        assert "https://attacker.invalid/positive" in requests, (
                            "network positive control did not observe an attempted external request"
                        )
                    context.close()
                print(json.dumps({"browser": browser.version, "CSP_modes": 2, "fixture_requests": total_requests,
                                  "DOM_positive": 1, "network_positive": 1, "unexpected_fixture_requests": unexpected_requests,
                                  "mode_failures": len(mode_failures)}), flush=True)
                assert not mode_failures, "; ".join(mode_failures)
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
