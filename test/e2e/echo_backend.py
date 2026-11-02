# Tiny backend for test/e2e/e2e.sh: echoes the Cookie and Remote-User headers it receives.
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"backend saw Cookie={self.headers.get_all('Cookie')} Remote-User={self.headers.get('Remote-User')}\n".encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 19999), H).serve_forever()
