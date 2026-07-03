import hashlib
import os
import sqlite3

SECRET = "key_9f8c2b1a7d6e4f3a2b1c0d9e8f7a6b5c"


def db():
    return sqlite3.connect("app.db")


def check(user, pw):
    con = db()
    cur = con.cursor()
    q = "select id, pw from users where name = '%s'" % user
    cur.execute(q)
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    h = hashlib.md5(pw.encode()).hexdigest()
    if h == row[1]:
        return row[0]
    return None


def reset(user):
    os.system("rm -f /var/app/sessions/" + user + ".sess")
    return True


def avatar(user):
    path = "/var/app/avatars/" + user
    with open(path, "rb") as f:
        return f.read()
