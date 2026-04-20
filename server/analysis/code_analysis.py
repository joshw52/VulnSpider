import json
import os
import re

from langchain_ollama import OllamaLLM

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")


def _parse_json_response(response: str) -> dict:
    """Parse a JSON response from the model, stripping markdown code fences if present."""
    # Strip markdown code fences (```json ... ``` or ``` ... ```)
    match = re.search(r'```(?:json)?\s*([\s\S]*?)```', response)
    if match:
        response = match.group(1)
    return json.loads(response.strip())


def scan_code_for_vulnerabilities(code: str, content_type: str = "html") -> dict:
    """
    Analyzes the submitted code for vulnerabilities using Ollama.

    Args:
        code (str): The code to be scanned for vulnerabilities.
        content_type (str): The type of content being scanned. One of "html", "js", or "css".

    Returns:
        dict: A dictionary containing the results of the vulnerability scan.
    """
    try:
        ollama = OllamaLLM(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL)

        if content_type == "js":
            preamble = "Analyze the following JavaScript code for security vulnerabilities:"
            type_definitions = """Type definitions (use only what applies to JavaScript):
- "secret": any hardcoded credentials, API keys, tokens, or passwords
- "script:internal": the JavaScript code itself"""
            content_checklist = """Vulnerability checklist — flag ANY of the following when found:

DOM XSS sinks (flag every occurrence regardless of whether the value appears controlled):
- innerHTML, outerHTML, insertAdjacentHTML assignments
- document.write() or document.writeln()
- element.setAttribute() with event handler attribute names
- location.href, location.replace(), location.assign() set to a non-literal value
- window.open() with a non-literal URL

Dangerous JS execution sinks:
- eval(), Function(), setTimeout(string), setInterval(string)
- script element creation via document.createElement("script")

Insecure patterns:
- Use of var instead of let/const (scope leakage risk)
- postMessage() without origin validation
- localStorage/sessionStorage storing sensitive-looking keys
- Hardcoded IPs, internal hostnames, or non-HTTPS URLs"""
        else:
            preamble = "Analyze the following web page for security vulnerabilities and issues:"
            type_definitions = """Type definitions:
- "comment": HTML comments (<!-- ... -->)
- "form": HTML <form> elements
- "link": <a> tags or other navigational links
- "package": referenced external libraries/packages (e.g., jQuery, Bootstrap CDN links)
- "secret": any hardcoded credentials, API keys, tokens, or passwords
- "script:external": <script src="..."> tags loading external files
- "script:internal": <script> blocks with inline JavaScript
- "script:in-element": event handler attributes on HTML elements (e.g., onerror, onclick, onload)"""
            content_checklist = """Vulnerability checklist — flag ANY of the following when found:

DOM XSS sinks (flag every occurrence regardless of whether the value appears controlled):
- innerHTML, outerHTML, insertAdjacentHTML assignments
- document.write() or document.writeln()
- element.setAttribute() with event handler attribute names
- location.href, location.replace(), location.assign() set to a non-literal value
- window.open() with a non-literal URL

Dangerous JS execution sinks:
- eval(), Function(), setTimeout(string), setInterval(string)
- script element creation via document.createElement("script")

Insecure patterns:
- Use of var instead of let/const (scope leakage risk)
- postMessage() without origin validation
- localStorage/sessionStorage storing sensitive-looking keys
- Hardcoded IPs, internal hostnames, or non-HTTPS URLs
- Commented-out credentials or debug code in HTML comments

Form issues:
- Missing CSRF token
- action URL using HTTP instead of HTTPS
- autocomplete not disabled on password fields
- password or sensitive fields with type="text"

Package issues:
- CDN-loaded packages without SRI (integrity + crossorigin attributes)
- References to known outdated or vulnerable library versions

Link issues:
- target="_blank" without rel="noopener noreferrer"
- javascript: protocol hrefs"""

        prompt = f"""
{preamble}

{code}

Scan the submitted content and identify findings. Only include a finding in the results if it has at least one vulnerability. Omit any finding where the vulnerabilities array would be empty.

Return ONLY a valid JSON object in this exact format, with no extra text:

{{
    "results": [
        {{
            "type": <"comment"|"form"|"link"|"package"|"secret"|"script:external"|"script:internal"|"script:in-element">,
            "lines": <line number(s) in the submitted content where this was found>,
            "content": <the relevant code snippet>,
            "vulnerabilities": [<list of vulnerability description strings, empty array if none>]
        }}
    ]
}}

{type_definitions}

{content_checklist}
"""

        response = ollama.invoke(prompt)
        data = _parse_json_response(response)
        # Filter out any results with no vulnerabilities (safety net in case the model ignores the prompt instruction)
        data["results"] = [r for r in data.get("results", []) if r.get("vulnerabilities")]
        return data

    except Exception as e:
        print(f"Ollama analysis failed: {e}")
        return {"error": str(e), "results": []}
