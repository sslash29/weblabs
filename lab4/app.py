from flask import Flask, request, make_response, render_template_string
import urllib.parse

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>CSRF & CRLF Local Lab</title></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 40px auto;">
    <h2>Search</h2>
    <form action="/search" method="GET">
        <input type="text" name="term" placeholder="Search...">
        <button type="submit">Search</button>
    </form>

    <h2>Update Email</h2>
    <form action="/update_email" method="POST">
        <!-- Hidden CSRF Token -->
        <input type="hidden" name="csrf" value="INVALID_TOKEN_999">
        <input type="email" name="email" placeholder="New Email" required>
        <button type="submit">Update</button>
    </form>
    
    <hr>
    <h3>Debug Info (Victim's Browser State)</h3>
    <p>Your current cookies:</p>
    <pre style="background: #eee; padding: 10px;">{{ cookies }}</pre>
</body>
</html>
"""

@app.route('/')
def index():
    response = make_response(render_template_string(HTML_TEMPLATE, cookies=request.cookies))
    if 'session' not in request.cookies:
        response.set_cookie('session', 'mock_session_id_456')
    if 'csrfKey' not in request.cookies:
        response.set_cookie('csrfKey', 'ORIGINAL_SECRET_KEY')
    return response

@app.route('/search')
def search():
    search_term = request.args.get('term', '')
    decoded_term = urllib.parse.unquote(search_term)
    
    response = make_response(f"You searched for: {decoded_term}. <br><br><a href='/'>Go back</a>")
    # Vulnerability: Unsanitized input passed directly to a header
    response.headers['Set-Cookie'] = f"LastSearch={decoded_term}"
    
    return response

@app.route('/update_email', strict_slashes=False, methods=['POST'])
def update_email():
    form_csrf = request.form.get('csrf')
    cookie_csrf_key = request.cookies.get('csrfKey')
    
    # The server expects this specific matched pair to validate the request
    if cookie_csrf_key == 'YOUR-KEY' and form_csrf == 'VALID_CSRF_TOKEN_123':
        new_email = request.form.get('email')
        return f"<h3 style='color:green'>SUCCESS: Email updated to {new_email}!</h3><a href='/'>Go back</a>"
    else:
        return f"<h3 style='color:red'>CSRF REJECTED</h3><p>Cookie key: {cookie_csrf_key}<br>Form token: {form_csrf}</p><a href='/'>Go back</a>", 403

if __name__ == '__main__':
    # host='0.0.0.0' is required for Docker to expose the port correctly
    app.run(host='0.0.0.0', port=5000)
