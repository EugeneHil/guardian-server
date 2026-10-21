"""Docs gate: docs/api.md must mention every route and error code used in src/*.cpp,
and README.md must carry the required headings and a Mermaid diagram."""
import glob
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


def sources():
    paths = sorted(glob.glob(os.path.join(ROOT, "src", "*.cpp")))
    return {os.path.basename(p): read("src", os.path.basename(p)) for p in paths}


def find_routes(text):
    routes = set(re.findall(r'"(/api/v1/[A-Za-z0-9/_-]*|/healthz)"', text))
    # Static allowlist entries: {"/app.js", "app.js", ...}
    routes.update(re.findall(r'\{"(/[A-Za-z0-9._/-]*)",\s*"[^"]+",\s*"', text))
    # Route loops: for (const char* path : {"/", "/app.js"})
    for body in re.findall(r"for \(const char\* path : \{([^}]*)\}", text):
        routes.update(re.findall(r'"(/[^"]*)"', body))
    return routes


def find_error_codes(text):
    codes = set()
    codes.update(re.findall(r'errorResponse\(\s*[^,"]+,\s*"(\w+)"', text))
    codes.update(re.findall(r'fallbackError\(\s*\d+,\s*"(\w+)"', text))
    codes.update(re.findall(r'\{"error",\s*"(\w+)"\}', text))
    codes.update(re.findall(r'case \d+:\s*return "(\w+)";', text))
    for pair in re.findall(r'\?\s*"(\w+)"\s*:\s*"(\w+)"', text):
        codes.update(pair)
    return codes


class ApiDocTest(unittest.TestCase):
    def test_extraction_finds_known_items(self):
        text = "\n".join(sources().values())
        self.assertIn("/api/v1/policy", find_routes(text))
        self.assertIn("/healthz", find_routes(text))
        self.assertIn("/app.js", find_routes(text))
        self.assertIn("not_found", find_error_codes(text))
        self.assertIn("invalid_events", find_error_codes(text))

    def test_every_route_is_documented(self):
        doc = read("docs", "api.md")
        for name, text in sources().items():
            for route in find_routes(text):
                self.assertIn(route, doc, "%s: route %s missing from docs/api.md" % (name, route))

    def test_every_error_code_is_documented(self):
        doc = read("docs", "api.md")
        for name, text in sources().items():
            for code in find_error_codes(text):
                self.assertIn(code, doc, "%s: error code %s missing from docs/api.md" % (name, code))


class ReadmeTest(unittest.TestCase):
    def test_required_headings(self):
        readme = read("README.md")
        for heading in ("Architecture", "Configuration", "Security notes", "Roadmap"):
            self.assertRegex(readme, r"(?m)^#{1,3} " + re.escape(heading) + r"\s*$")

    def test_mermaid_block(self):
        self.assertIn("```mermaid", read("README.md"))


if __name__ == "__main__":
    unittest.main()
