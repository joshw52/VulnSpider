import json
import os
import re

from langchain_community.llms import Ollama

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")


def _parse_json_response(response: str) -> dict:
    """Parse a JSON response from the model, stripping markdown code fences if present."""
    # Strip markdown code fences (```json ... ``` or ``` ... ```)
    match = re.search(r'```(?:json)?\s*([\s\S]*?)```', response)
    if match:
        response = match.group(1)
    return json.loads(response.strip())


def scan_code_for_vulnerabilities(code: str) -> dict:
    """
    Analyzes the submitted HTML, CSS, or JavaScript code for vulnerabilities using Ollama.

    Args:
        code (str): The HTML, CSS, or JavaScript code to be scanned for vulnerabilities.

    Returns:
        dict: A dictionary containing the results of the vulnerability scan.
    """
    try:
        ollama = Ollama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL)

        prompt = f"""
Analyze the following web page for security vulnerabilities and issues:

{code}

Scan the submitted content and identify findings including HTML comments, forms, links, packages, secrets, and scripts. Only include a finding in the results if it has at least one vulnerability. Omit any finding where the vulnerabilities array would be empty.

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

Type definitions:
- "comment": HTML comments (<!-- ... -->)
- "form": HTML <form> elements
- "link": <a> tags or other navigational links
- "package": referenced external libraries/packages (e.g., jQuery, Bootstrap CDN links)
- "secret": any hardcoded credentials, API keys, tokens, or passwords
- "script:external": <script src="..."> tags loading external files
- "script:internal": <script> blocks with inline JavaScript
- "script:in-element": event handler attributes on HTML elements (e.g., onerror, onclick, onload)
"""

        response = ollama.invoke(prompt)
        data = _parse_json_response(response)
        # Filter out any results with no vulnerabilities (safety net in case the model ignores the prompt instruction)
        data["results"] = [r for r in data.get("results", []) if r.get("vulnerabilities")]
        return data

    except Exception as e:
        print(f"Ollama analysis failed: {e}")
        return {"error": str(e), "results": []}
