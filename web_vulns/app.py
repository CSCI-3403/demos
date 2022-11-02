from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
import logging
from pathlib import Path
import random
import sqlite3
import sys
from typing import Any, Dict, Optional

import click
from flask import Flask, abort, make_response, redirect, request, render_template, session, url_for
from flask_wtf import FlaskForm # type: ignore
from flask_login import current_user, login_required, login_user, LoginManager, logout_user, UserMixin # type: ignore
from wtforms import StringField, PasswordField, SubmitField
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
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['SESSION_COOKIE_SECURE'] = True
app.secret_key = "zxcvzxcvzxcvzxcvzvcbncvbnfh"

DATABASE = "./data/users.sqlite3"

@dataclass
class Document:
    id: int
    owner: str
    contents: str

@dataclass
class User(UserMixin):
    username: str

    def get_id(self) -> str:
        return self.username

class CSRFForm(FlaskForm):
    def __init__(self):
        self.Meta.csrf = csrf_level() > 0
        super().__init__()

login_manager = LoginManager(app)
login_manager.login_view = 'login'

def xss_level() -> bool:
    return session.get("xss", False)

def csrf_level() -> bool:
    return session.get("csrf", False)

def sqli_level() -> bool:
    return session.get("sqli", False)

def escape_xss(html: str) -> str:
    if xss_level() >= 2:
        return html.replace("<", "&lt;").replace(">", "&gt;")
    else:
        return html

def execute_sql(query: str, *pargs, safe: bool = False, script: bool = False) -> Any:
    connection = sqlite3.connect(DATABASE)
    cur = connection.cursor()

    level = sqli_level()
    try:
        if level == 0 and not safe:
            q = query.format(*pargs)
            if not script:
                logger.info("Running unsafe query: {}".format(q))
                return cur.execute(q).fetchall()
            else:
                logger.info("Running unsafe script: {}".format(q))
                return cur.executescript(q).fetchall()
        else:
            q = query.replace("'{}'", "?")
            return cur.execute(q, pargs).fetchall()
    except (sqlite3.Warning, sqlite3.OperationalError) as e:
        logger.info(e)
        raise RuntimeError("Error running query: {}".format(q))
    finally:
        connection.commit()
        cur.close()

def init():
    connection = sqlite3.connect(DATABASE)
    cur = connection.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT);
    CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, contents TEXT);
    CREATE TABLE IF NOT EXISTS creditcards (ccnumber INTEGER PRIMARY KEY, code INTEGER, user TEXT);

    INSERT INTO users VALUES ('admin', 'Sw0rdf1sh!') ON CONFLICT DO NOTHING;
    INSERT INTO documents (id, owner, contents) VALUES (0, 'admin', 'Example document') ON CONFLICT DO NOTHING;
    INSERT INTO creditcards VALUES (123456789012, 123, 'admin') ON CONFLICT DO NOTHING;
    """)
    connection.commit()
    cur.close()

@login_manager.user_loader
def load_user(username: str) -> Optional[User]:
    return User(username)

@app.before_request
def set_id():
    if 'id' not in session:
        session['id'] = random.randint(0, 1000)

@app.context_processor
def inject_debug_info() -> Dict[str, Any]:
    return {
        'xss_level': xss_level(),
        'csrf_level': csrf_level(),
        'sqli_level': sqli_level(),
    }

@app.route('/')
@login_required
def index():
    documents = [Document(d[0], d[1], d[2]) for d in
        execute_sql("SELECT * FROM documents")]
    return render_template('index.html',  user=current_user, documents=documents)

@app.route('/search')
@login_required
def search():
    query = request.args.get('query')
    documents = [Document(d[0], d[1], d[2]) for d in
        execute_sql("SELECT * FROM documents WHERE contents LIKE ?", f'%{query}%', safe=True)]
    # results = [d for d in enumerate(documents) if query.lower() in d[1].contents.lower()]
    resp = make_response(render_template('search.html',  user=current_user, query=escape_xss(query), documents=documents))

    if xss_level() >= 1:
        resp.headers["Content-Security-Policy"] = "script-src 'self' kit.fontawesome.com"

    return resp

@app.route('/document/<id>')
@login_required
def document(id):
    documents = [Document(d[0], d[1], d[2]) for d in
        execute_sql("SELECT * FROM documents WHERE id=?", id, safe=True)]

    if not documents:
        abort(404)
    return render_template('document.html', user=current_user, document=escape_xss(documents[0]))

class CreateForm(CSRFForm):
    content = StringField('Content', widget=TextArea(), validators=[DataRequired(), Length(max=2048)])

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = CreateForm()

    if form.validate_on_submit():
        execute_sql("INSERT INTO documents (owner, contents) VALUES (?, ?)", current_user.username, form.content.data, safe=True)
        return redirect(url_for('index'))
    return render_template('create.html', user=current_user, form=form)

class LoginForm(CSRFForm):
    username = StringField('Username', [Length(min=1)])
    password = PasswordField('Password')
    login = SubmitField(label='Log In')
    create = SubmitField(label='Create')

@app.route('/login', methods=['GET', 'POST'])
def login() -> Response:
    form = LoginForm()

    if form.validate_on_submit():
        create = form.create.data
        username = form.username.data
        password = form.password.data

        try:
            if create:
                (count, *_), *_ = execute_sql(
                    "SELECT COUNT(*) FROM users WHERE username='{}'",
                    username)

                if count == 0:
                    logger.info("Creating new user: {}".format(username))
                    execute_sql("INSERT INTO users (username, password) VALUES ('{}', '{}')", username, password, script=True)
                    login_user(User(username=username))
                else:
                    logger.info("Failed creation attempt for user: {}".format(username))
                    form.username.errors.append("A user with the name {} already exists".format(username))
                    return render_template('login.html', form=form)
            else:
                users = execute_sql(
                    "SELECT username FROM users WHERE username='{}' AND password='{}'",
                    username,
                    password)

                if users:
                    logger.info("Successful login attempt for user: {}".format(username))
                    (username, *_), *_ = users
                    login_user(User(username))
                else:
                    logger.info("Failed login attempt for user: {}".format(username))
                    form.password.errors.append('Password is incorrect, or that user does not exist')
                    return render_template('login.html', form=form)

            next = request.args.get('next')
            if next and request.host in next:
                return redirect(next)
            return redirect(url_for('index'))

        except RuntimeError as e:
            logger.info("SQL injection error: {}".format(str(e)))
            form.username.errors.append(str(e))

    return render_template('login.html', form=form)

@app.route('/vulns', methods=['POST'])
def csrf() -> Response:
    for vuln in ["xss", "csrf", "sqli"]:
        session[vuln] = int(request.form.get(vuln, 0))

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

@app.route('/reset')
def reset() -> None:
    Path(DATABASE).rename(f"./data/{datetime.now().strftime('%y-%m-%dT%H-%M-%S')}-users.sqlite3.bak")
    init()

@click.command()
@click.option('--debug', is_flag=True)
@click.option('--port', default=80)
def main(debug: bool, port: int) -> None:
    init()
    app.run("0.0.0.0", debug=debug, port=port)

if __name__ == '__main__':
    main()