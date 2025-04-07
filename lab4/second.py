from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/')
def index():
    name = escape(request.args.get('name', 'Гость'))
    return render_template_string(f'<h1>Привет, {name}!</h1>')

if __name__ == '__main__':
    app.run(debug=True)
