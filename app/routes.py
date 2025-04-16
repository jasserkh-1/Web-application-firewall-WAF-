from flask import Blueprint, render_template, request
from .waf import analyze_request

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        # Here we grab the 'payload' from the form, but also pass 'request'
        # so the WAF can see headers, cookies, query params, etc.
        payload = request.form.get('payload', '')
        result = analyze_request(payload, request_obj=request)
    return render_template('index.html', result=result)

@main.route('/api/analyze', methods=['POST'])
def analyze_api():
    # Same idea for JSON requests
    data = request.get_json() or {}
    payload = data.get('payload', '')
    result = analyze_request(payload, request_obj=request)
    return {'result': result}
