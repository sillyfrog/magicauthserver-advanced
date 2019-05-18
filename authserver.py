#!/usr/bin/env python3

import flask
from flask import request
from flask_sqlalchemy import SQLAlchemy
import pyotp
import qrcode
import argparse
import crypt
import getpass
import os
import secrets
import sys
import base64
from io import BytesIO
import time
import redis

from auth import config

COOKIE = "magicproxyauth"
AUTHFORM = "authform.html"

# The expiry time of cookies set with out authenticating
UNAUTH_TIMEOUT = 60  # XXX
authdcookies = set()

r = redis.Redis(
    host=config.getconf("redis_host", default="redis"), decode_responses=True
)

app = flask.Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = config.getconf("db_uri", raiseerror=True)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class WebUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text(), unique=True, nullable=False)
    password = db.Column(db.Text())
    otp = db.Column(db.Text())
    level = db.Column(db.Integer(), nullable=False, default=0)


class BasicUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text(), unique=True, nullable=False)
    password = db.Column(db.Text(), nullable=False)


OTP_TEMPLATE = """
e = document.getElementById("forotp");
e.innerHTML="Scan this code in your Authy app:<br><img src='data:image/png;base64,{}'>";
error("Verify OTP Code");
"""


@app.route("/", defaults={"path": ""}, methods=["GET"])
@app.route("/<path:path>", methods=["GET"])
def index(path):
    cookie, username = getauthcookie()
    if username:
        return "Auth {}".format(username)

    basicauth = request.headers.get("Authorization")
    if basicauth:
        parts = basicauth.split()
        if len(parts) == 2:
            if parts[0].lower() == "basic":
                try:
                    details = base64.b64decode(parts[1]).decode()
                    username, password = details.split(":", 1)
                except:
                    username, password = (None, None)
                if checkbasicauthlogin(username, password):
                    return "Auth"

    resp = flask.make_response(flask.render_template("authform.jinja"))
    if cookie is None:
        authcookie = gencookie()
        resp.set_cookie(
            COOKIE,
            authcookie,
            domain=COOKIE_DOMAIN,
            max_age=2147483647,
            secure=COOKIE_SECURE,
        )
    return resp, 401


@app.route("/", defaults={"path": ""}, methods=["POST"])
@app.route("/<path:path>", methods=["POST"])
def submit(**path):
    username = request.headers.get("X-set-username")
    password = request.headers.get("X-set-password")
    otp = request.headers.get("X-set-otp")
    cookie, _ = getauthcookie()

    if username:
        username = username.lower()

    if cookie:
        user = checklogin(username, password)
        if user:
            otpcheck = checkotp(user, otp)
            if otpcheck == None:
                # Username and password is OK, but we need to create a OTP for them
                otpuri = addotp(user)
                img = qrcode.make(otpuri)
                buf = BytesIO()
                img.save(buf, format="PNG")
                img_str = base64.b64encode(buf.getvalue()).decode()
                return OTP_TEMPLATE.format(img_str), 401

            elif otpcheck == True:
                setauthcookie(cookie, user.username)
                return "location.reload();", 401
            else:
                time.sleep(0.5)
                return "error('Wrong username, password or code');", 401
    else:
        time.sleep(1)
        return "error('Wrong username/password or cookie not set');", 401


def checkotp(user, otp):
    unverifiedkey = "unverified_{}".format(user.username)
    if user.otp:
        otphash = user.otp
    else:
        otphash = r.get(unverifiedkey)
        if not otphash:
            return None
    totp = pyotp.TOTP(otphash)
    verified = totp.verify(otp, valid_window=1)
    if r.exists(unverifiedkey):
        if verified:
            r.delete(unverifiedkey)
            user.otp = otphash
            db.session.commit()
        else:
            # We have an OTP code for this user, but they have not yet verified it.
            return None
    return verified


def addotp(user):
    unverifiedkey = "unverified_{}".format(user.username)
    otphash = r.get(unverifiedkey)
    if not otphash:
        otphash = pyotp.random_base32()
        r.set(unverifiedkey, otphash)
    totp = pyotp.TOTP(otphash)
    return totp.provisioning_uri(user.username, COOKIE_DOMAIN)


def getauthcookie():
    cookie = request.cookies.get(COOKIE)
    if cookie:
        username = r.get("cookie_{}".format(cookie))
        if username is not None:
            return cookie, username
    return None, None


def setauthcookie(cookie, username):
    key = "cookie_{}".format(cookie)
    r.set(key, username)


def gencookie():
    newcookie = secrets.token_urlsafe()
    key = "cookie_{}".format(newcookie)
    r.set(key, "")
    r.expire(key, UNAUTH_TIMEOUT)
    return newcookie


def checklogin(username, password):
    user = WebUser.query.filter_by(username=username.lower()).first()
    if user:
        if user.password == crypt.crypt(password, user.password):
            return user
    return None


def checkbasicauthlogin(username, password):
    if not username or not password:
        return False
    username = username.lower()
    user = BasicUser.query.filter_by(username=username.lower()).first()
    if user:
        if user.password == crypt.crypt(password, user.password):
            return True
    return False


def addlogin(username, password, admin=False):
    username = username.lower()
    passwordhash = crypt.crypt(password, crypt.mksalt())
    if admin:
        level = 100
    else:
        level = 0
    user = WebUser(username=username, password=passwordhash, level=level)
    db.session.add(user)
    db.session.commit()


def addbasiclogin(username):
    username = username.lower()
    password = secrets.token_urlsafe()
    print("New password for {}: {}".format(username, password))
    passwordhash = crypt.crypt(password, crypt.mksalt())
    user = BasicUser(username=username, password=passwordhash)
    db.session.add(user)
    db.session.commit()
    return password


def promptpassword():
    while 1:
        password1 = getpass.getpass("Password: ")
        password2 = getpass.getpass("Re-enter Password: ")
        if password1 == password2:
            return password1
        print("Passwords don't match!")


def loadconfig():
    global COOKIE_DOMAIN, COOKIE_SECURE, LISTEN_PORT
    COOKIE_DOMAIN = config.getconf("cookie_domain", raiseerror=True)
    COOKIE_SECURE = config.getbool("cookie_secure")
    LISTEN_PORT = config.getint("listen_port", 80)


def main():
    loadconfig()

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--adduser", action="store_true")
    parser.add_argument(
        "--debug", action="store_true", help="Run flask in debug mode for development."
    )
    args = parser.parse_args()
    if args.adduser:
        username = input("Username: ")
        password = promptpassword()
        addlogin(username, password, admin=True)
    else:
        app.run(host="0.0.0.0", port=LISTEN_PORT, debug=args.debug)


def log(msg):
    sys.stderr.write("{}\n".format(msg))
    sys.stderr.flush()


if __name__ == "__main__":
    main()
