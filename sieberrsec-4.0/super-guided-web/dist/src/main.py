from flask import Flask, render_template, render_template_string, request, Response, make_response, redirect, jsonify
import os
import uuid

import sqlite3

app = Flask(__name__)


def safe_path(path, safe_dir="./content"):
    safe_dir = os.path.realpath(safe_dir)
    if os.path.commonprefix((os.path.realpath(path),safe_dir)) != safe_dir:
        return False
    return True


@app.route("/guides")
def guide():
    uid = request.cookies.get("uid")
    if not uid or not os.path.exists(f"./content/databases/{uid}.db"):
        return redirect("/")
    if not safe_path(f"./content/databases/{uid}.db", "./content/databases"):
        return "Die hacker!"
    search = request.args.get("search")
    results = []
    conn = sqlite3.connect(f"./content/databases/{uid}.db")
    c = conn.cursor()
    try:
        c.execute(f"select * from guides where name like '%{search}%'")
    except Exception as e:
        c.executescript(f"select * from guides where name like '%{search}%'")
    for row in c.fetchall():
        result = {}
        result["name"] = row[1]
        result["id"] = row[0]
        results.append(result)
    conn.commit()
    conn.close()
    return jsonify(results)

@app.route("/guides/view/<id>")
def view_guide(id):
    uid = request.cookies.get("uid")
    if not uid or not os.path.exists(f"./content/databases/{uid}.db"):
        return redirect("/")
    if not safe_path(f"./content/databases/{uid}.db", "./content/databases"):
        return "Die hacker!"
    conn = sqlite3.connect(f"./content/databases/{uid}.db")
    c = conn.cursor()
    id = int(id)
    results = list(c.execute(f"select path from guides where id = {id}"))
    conn.commit()
    conn.close()
    if len(results) != 1:
        return "Not found"
    if id > 3:
        print(uid, id, results)

    path = results[0][0]

    if not safe_path(f"./content/guides/{path}", "./content"):
        return "Die smarter hacker!"
        
    try:
        contents = open(f"./content/guides/{path}","rb").read()
        # Strip out unicode characters
        contents = bytes(x for x in contents if x < 128)
        return render_template_string(contents.decode("ascii"))
    except Exception as e:
        return f"There was an error processing your request: {e}"

    


@app.route("/")
def index():
    resp = make_response(render_template("index.html"))
    uid = request.cookies.get("uid")
    if uid and os.path.exists(f"./content/databases/{uid}.db"):
        return resp
    id = str(uuid.uuid4())
    resp.set_cookie("uid", id)
    conn = sqlite3.connect(f"./content/databases/{id}.db")
    c = conn.cursor()
    c.executescript("CREATE TABLE IF NOT EXISTS guides (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, path TEXT)")
    c.executescript("insert into guides(name,path) values('SSTI','server-side-template-injection.html')")
    c.executescript("insert into guides(name,path) values('LFI','local-file-inclusion.html')")
    c.executescript("insert into guides(name,path) values('SQLI','sql-injection.html')")
    conn.commit()
    conn.close()
    return resp
    
