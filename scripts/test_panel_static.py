import os
import re
import unittest
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "web")
ALLOWED_ASSETS = {"/app.js", "/panel.css", "/tokens.css"}


def read(name):
    with open(os.path.join(WEB, name), encoding="utf-8") as fh:
        return fh.read()


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.problems = []
        self.refs = []

    def handle_starttag(self, tag, attrs):
        names = dict(attrs)
        if tag == "script":
            if "src" not in names:
                self.problems.append("inline <script>")
            self.refs.append(names.get("src"))
        if tag == "style":
            self.problems.append("inline <style>")
        if tag == "link":
            self.refs.append(names.get("href"))
        if tag in ("img", "iframe", "audio", "video", "source", "embed", "object"):
            self.refs.append(names.get("src") or names.get("data"))
        for name in names:
            if name.startswith("on"):
                self.problems.append("event attribute " + name)
            if name == "style":
                self.problems.append("style attribute")


class PanelStaticTest(unittest.TestCase):
    def test_app_js_uses_no_html_injection_apis(self):
        source = read("app.js")
        forbidden = [
            r"\.innerHTML\b",
            r"\.outerHTML\b",
            r"\binsertAdjacentHTML\b",
            r"\bdocument\.write(ln)?\b",
            r"\beval\s*\(",
            r"\bnew\s+Function\b",
            r"\bFunction\s*\(",
            r"\bsetTimeout\s*\(\s*['\"`]",
            r"\bsetInterval\s*\(\s*['\"`]",
            r"\bimport\s*\(",
            r"\bcreateContextualFragment\b",
            r"\bDOMParser\b",
            r"\bsrcdoc\b",
            r"\.setAttribute\s*\(\s*['\"]on",
            r"\blocalStorage\b",
            r"\bsessionStorage\b",
            r"\bXMLHttpRequest\b",
            r"https?://",
        ]
        for pattern in forbidden:
            self.assertIsNone(re.search(pattern, source), pattern)

    def test_app_js_fetches_with_same_origin_no_store(self):
        source = read("app.js")
        self.assertIn('credentials: "same-origin"', source)
        self.assertIn('cache: "no-store"', source)

    def test_app_js_marks_state_changing_requests(self):
        source = read("app.js")
        self.assertRegex(source, r'headers\["X-Warden-Request"\]\s*=\s*"1"')
        self.assertIn('method !== "GET"', source)

    def test_app_js_is_a_classic_script(self):
        source = read("app.js")
        self.assertIsNone(re.search(r"^\s*(import|export)\s", source, re.M))

    def test_index_html_has_no_inline_script_style_or_handlers(self):
        parser = _Collector()
        parser.feed(read("index.html"))
        self.assertEqual(parser.problems, [])

    def test_html_references_only_allowlisted_assets(self):
        parser = _Collector()
        parser.feed(read("index.html"))
        self.assertEqual({r for r in parser.refs}, ALLOWED_ASSETS)

    def test_html_basics(self):
        html = read("index.html")
        self.assertIn('lang="en"', html)
        self.assertIn('role="tablist"', html)
        self.assertIn("aria-live", html)

    def test_load_policy_guards_against_failed_initial_load(self):
        source = read("app.js")
        self.assertIn("res.status !== 200", source)
        self.assertIn("typeof active.version", source)
        self.assertIn("showLoadError", source)
        html = read("index.html")
        self.assertIn('id="retry"', html)
        self.assertRegex(html, r'<textarea[^>]*\bdisabled\b')
        self.assertRegex(html, r'<button[^>]*id="save-draft"[^>]*\bdisabled\b')

    def test_save_and_publish_are_guarded_and_exclusive(self):
        source = read("app.js")
        self.assertIn("if (!state.editorLoaded || state.busy)", source)
        self.assertIn("setBusy(", source)

    def test_decision_other_than_deny_allow_is_neutral(self):
        source = read("app.js")
        self.assertIn('"allow"', source)
        self.assertIn("badge neutral", source)

    def test_color_scheme_declared(self):
        self.assertIn('name="color-scheme"', read("index.html"))

    def test_css_uses_token_variables_for_colors(self):
        css = read("panel.css")
        self.assertIsNone(re.search(r"#[0-9A-Fa-f]{3,8}\b", css))
        self.assertIsNone(re.search(r"\b(rgb|rgba|hsl|hsla)\s*\(", css))
        self.assertIsNone(re.search(r"@import|url\s*\(", css))
        self.assertIn("var(--color-", css)

    def test_css_only_uses_defined_variables(self):
        defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", read("tokens.css")))
        used = set(re.findall(r"var\(\s*(--[a-z0-9-]+)", read("panel.css")))
        self.assertEqual(used - defined, set())

    def test_process_column_shows_path_line(self):
        source = read("app.js")
        self.assertRegex(source, r"function processLines\s*\(")
        self.assertRegex(source, r'el\(\s*"div"\s*,\s*"proc-path mono"')
        self.assertRegex(source, r"\.title\s*=\s*path")
        self.assertRegex(source, r"processLines\(\s*e\.process")
        self.assertRegex(source, r"processLines\(\s*e\.responsible")
        self.assertIsNone(re.search(r'proc\s*\+=\s*" ← "', source))

    def test_process_path_class_is_styled_and_wraps(self):
        css = read("panel.css")
        match = re.search(r"\.proc-path\s*\{([^}]*)\}", css)
        self.assertIsNotNone(match)
        self.assertIn("overflow-wrap", match.group(1))
        self.assertIn("var(--color-text-secondary)", match.group(1))
        self.assertIn("var(--font-caption-size)", match.group(1))


if __name__ == "__main__":
    unittest.main()
