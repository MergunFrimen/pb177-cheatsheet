from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Get content length
        content_length = int(self.headers['Content-Length'])
        # Read the POST data
        post_data = self.rfile.read(content_length).decode('utf-8')
        # Decode URL-encoded data
        parsed_data = parse_qs(post_data)

        # Print parsed data
        # print("Received POST data (raw):", post_data)
        print("Decoded POST data:", parsed_data)

        # Send response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"POST data received")

httpd = HTTPServer(('0.0.0.0', 8080), SimpleHTTPRequestHandler)
print("Simple HTTP server listening on port 8080")
httpd.serve_forever()
