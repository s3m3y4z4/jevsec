"""Mock di un endpoint /v1/systemone per validare l'harness senza GPU.

Risponde in modo deterministico: choice = prima opzione con probabilità fissa,
score = livello centrale, noul = 0.5. Serve solo a testare la plumbings.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

PORT = 8099
FIXED_PROBABILITY = 0.62


def canned_answer(question: dict[str, Any]) -> dict[str, Any]:
    if question["type"] == "choice":
        options = list(question["criteria"].keys())
        return {"type": "choice", "choice": options[0], "confidence": FIXED_PROBABILITY,
                "probabilities": {option: FIXED_PROBABILITY if option == options[0] else 0.38 / max(len(options) - 1, 1) for option in options}}
    if question["type"] == "score":
        levels = question["criteria"]
        middle = len(levels) // 2
        return {"type": "score", "score": float(middle), "confidence": FIXED_PROBABILITY,
                "probabilities": {str(i): (FIXED_PROBABILITY if i == middle else 0.38 / max(len(levels) - 1, 1)) for i in range(len(levels))}}
    return {"type": "noul", "noul": 0.5}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/v1/systemone":
            self.send_error(404)
            return
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        answers = {name: canned_answer(question) for name, question in payload["questions"].items()}
        body = json.dumps({"model": "mock-1", "answers": answers, "usage": {}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        pass


if __name__ == "__main__":
    print(f"mock System One in ascolto su :{PORT}")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
