from dataclasses import dataclass
from glob import escape
import logging
import random
import sys
from typing import Any, Dict, Optional
import click
from flask import Flask, make_response, redirect, request, render_template, session, url_for

from flask_wtf import FlaskForm # type: ignore
from flask_login import current_user, login_required, login_user, LoginManager, logout_user, UserMixin # type: ignore
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length # type: ignore
from wtforms.widgets import TextArea # type: ignore
from werkzeug.wrappers import Response

class ContextFilter(logging.Filter):
    def filter(self, record):
        record.id = session.get('id')
        record.ip = request.remote_addr
        return True

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addFilter(ContextFilter())
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(ip)s (ID #%(id)s):%(message)s'))
logger.addHandler(handler)

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.secret_key = "asdfasdfasdfasdfqwerqwer"

@dataclass
class Document:
    owner: str
    contents: str

documents = [Document(owner='admin', contents='Test document')]

@dataclass
class User(UserMixin):
    username: str
    password: str

    def get_id(self) -> str:
        return self.username

class CSRFForm(FlaskForm):
    def __init__(self):
        self.Meta.csrf = not csrf_enabled()
        super().__init__()

users = {
    "admin": User("admin", "Sw0rdf1sh!")
}

login_manager = LoginManager(app)
login_manager.login_view = 'login'

def xss_enabled():
    return session.get("xss", False)

def csrf_enabled():
    return session.get("csrf", False)

def sqli_enabled():
    return session.get("sqli", False)

def escape_xss(html: str) -> str:
    if xss_enabled():
        return html
    else:
        return html.replace("<", "&lt;").replace(">", "&gt;")

@login_manager.user_loader
def load_user(username: str) -> Optional[User]:
    return users.get(username)

@app.before_request
def set_id():
    if 'id' not in session:
        session['id'] = random.randint(0, 1000)

@app.context_processor
def inject_debug_info() -> Dict[str, Any]:
    return {
        'xss_enabled': xss_enabled(),
        'csrf_enabled': csrf_enabled(),
        'sqli_enabled': sqli_enabled(),
    }

@app.route('/')
@login_required
def index():
    return render_template('index.html',  user=current_user, documents=enumerate(documents))

@app.route('/search')
@login_required
def search():
    query = request.args.get('query')
    results = [d for d in enumerate(documents) if query.lower() in d[1].contents.lower()]
    resp = make_response(render_template('search.html',  user=current_user, query=query, documents=results))

    if not xss_enabled():
        resp.headers["Content-Security-Policy"] = "script-src 'self' kit.fontawesome.com"

    return resp

@app.route('/document/<id>')
@login_required
def document(id):
    return render_template('document.html', user=current_user, document=escape_xss(documents[int(id)]))

class CreateForm(CSRFForm):
    content = StringField('Content', widget=TextArea(), validators=[DataRequired(), Length(max=2048)])

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = CreateForm()

    if form.validate_on_submit():
        documents.append(Document(owner=current_user.username, contents=form.content.data))
        return redirect(url_for('index'))

    return render_template('create.html', user=current_user, form=form)

def add_user(username, password):
    users[username] = User(username, password)

def get_user(username, password):
    if username in users:
        return users[username]
    else:
        return None

class LoginForm(CSRFForm):
    username = StringField('Username', [Length(min=1)])
    password = PasswordField('Password', [Length(min=1)])

@app.route('/login', methods=['GET', 'POST'])
def login() -> Response:
    form = LoginForm()

    if form.validate_on_submit():
        user = get_user(form.username.data, form.password.data)

        if not user:
            user = User(form.username.data, form.password.data)
            users[form.username.data] = user
        elif user.password != form.password.data:
            form.password.errors.append('Username or password is incorrect!')
            return render_template('login.html', form=form)

        login_user(user)

        next = request.args.get('next')
        if next and request.host in next:
            return redirect(next)
        return redirect(url_for('index'))

    return render_template('login.html', form=form)

@app.route('/vulns', methods=['POST'])
def csrf() -> Response:
    print("Vulns called")
    print(request.form)
    for vuln in ["xss", "csrf", "sqli"]:
        print(vuln)
        if vuln in request.form:
            print("Enabled" + vuln)
            session[vuln] = True
        elif vuln in session:
            print("Disabled" + vuln)
            del session[vuln]

    if request.host in request.referrer:
        return redirect(request.referrer)

    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout() -> Response:
    logout_user()
    return redirect(url_for('index'))

@app.route('/save')
def safe() -> Response:
    import json
    with open('save.json', 'w') as f:
        f.write(json.dumps([d.__dict__ for d in documents]))
    return redirect(url_for('index'))

@click.command()
@click.option('--debug', is_flag=True)
@click.option('--port', default=80)
def main(debug: bool, port: int) -> None:
    app.run(debug=debug, port=port)

if __name__ == '__main__':
    main()