"""DELIBERATELY VULNERABLE - sample input for the scanner. Never run or deploy."""

import os
import sqlite3

from flask import Flask, request, send_file

app = Flask(__name__)


def get_connection():
    return sqlite3.connect("users.db")


@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    # VULNERABLE: SQL injection - the query is built by string concatenation.
    query = "SELECT id, name, email FROM users WHERE name = '" + name + "'"
    rows = get_connection().execute(query).fetchall()
    return {"users": rows}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: OS command injection - user input reaches a shell.
    os.system("ping -c 1 " + host)
    return {"pinged": host}


@app.route("/files")
def download():
    filename = request.args.get("name", "")
    # VULNERABLE: path traversal - "../" in the name escapes the uploads folder.
    return send_file(os.path.join("uploads", filename))
