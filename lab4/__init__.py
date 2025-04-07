from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', 'Гость')
    return render_template_string(f'<h1>Привет, {name}!</h1>')

if __name__ == '__main__':
    app.run(debug=True)

# http://127.0.0.1:5000/?name=<script>alert('XSS')</script>
