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
import json

from auth import config

COOKIE = "magicproxyauth"
AUTHFORM = "authform.html"

# The expiry time of cookies set with out authenticating
UNAUTH_TIMEOUT = 900
# The expiry time of an inactive cookie, cache updated every check
AUTHED_TIMEOUT = 35 * 24 * 3600  # 35 days
authdcookies = set()

r = redis.Redis(
    host=config.getconf("redis_host", default="redis"), decode_responses=True
)

app = flask.Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = config.getconf("db_uri", raiseerror=True)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

ADMIN_LEVEL = 100
NORMAL_LEVEL = 0


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
        # Check the user is still real
        user = WebUser.query.filter_by(username=username).first()
        if user:
            return "Auth {}".format(user.username)
        else:
            print("Authed user no longer valid: {}".format(username))
            delcookie(cookie)

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
        setcookie(resp)
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
                time.sleep(1)
    else:
        time.sleep(1)
        resp = flask.make_response(
            "error('Wrong username/password or cookie not set');"
        )
        setcookie(resp)
        return resp, 401
    return "error('Wrong username, password or code');", 401


def setcookie(resp):
    authcookie = gencookie()
    resp.set_cookie(
        COOKIE,
        authcookie,
        domain=COOKIE_DOMAIN,
        max_age=2147483647,
        secure=COOKIE_SECURE,
    )


@app.route("/magicauth/users/manage", methods=["GET", "POST"])
def manageusers():
    cookie, username = getauthcookie()
    if not username:
        # Shouldn't get here, but it's possible
        return index(None)
    user = WebUser.query.filter_by(username=username).first()
    if not user or user.level < ADMIN_LEVEL:
        return "You must be admin to access this page."
    if request.method == "GET":
        return flask.render_template("users.html", activeuser=json.dumps(user.username))
    elif request.method == "POST":
        content = request.json
        ret = {"ok": False}
        try:
            if content.get("action") == "getusers":
                data = []
                for user in WebUser.query.order_by(WebUser.username).all():
                    data.append(
                        {
                            "username": user.username,
                            "level": user.level,
                            "tokenset": bool(user.otp),
                        }
                    )
                ret["users"] = data
                ret["ok"] = True

            elif content.get("action") == "adduser":
                password = secrets.token_urlsafe()[:8]
                addlogin(content["username"], password, content["level"] == ADMIN_LEVEL)
                ret[
                    "msg"
                ] = "User <strong>{}</strong> added, their new password is: <span style=\"font-family: 'Courier New', Courier, monospace;\">{}</span>".format(
                    content["username"], password
                )
                ret["ok"] = True

            elif content.get("action") == "deleteuser":
                deleteuser(content["username"])
                ret["msg"] = "User <strong>{}</strong> deleted".format(
                    content["username"]
                )
                ret["ok"] = True

            elif content.get("action") == "makeadmin":
                updateuserlevel(content["username"], ADMIN_LEVEL)
                ret["msg"] = "User <strong>{}</strong> is now Admin".format(
                    content["username"]
                )
                ret["ok"] = True

            elif content.get("action") == "demoteadmin":
                updateuserlevel(content["username"], NORMAL_LEVEL)
                ret["msg"] = "User <strong>{}</strong> is no longer an Admin".format(
                    content["username"]
                )
                ret["ok"] = True

            elif content.get("action") == "resettoken":
                resetusertoken(content["username"])
                ret["msg"] = "User <strong>{}</strong> Token Reset".format(
                    content["username"]
                )
                ret["ok"] = True

        except Exception as e:
            ret["msg"] = "<strong>Error!</strong>: {}".format(e)
        return flask.jsonify(ret)


@app.route("/magicauth/users/self", methods=["GET", "POST"])
def manageself():
    cookie, username = getauthcookie()
    if not username:
        # Shouldn't get here, but it's possible
        return index(None)
    if request.method == "GET":
        return flask.render_template("self.html", activeuser=username)
    elif request.method == "POST":
        content = request.json
        newpassword = content.get("newpassword")
        if not newpassword:
            return "No password", 401
        if len(newpassword) < 8:
            return "Too Short!", 401
        if newpassword.lower() == "password":
            return "That's not a password", 401
        resetuserpassword(username, newpassword)
        return "ok"


@app.route("/magicauth/users/logout", methods=["GET", "POST"])
def logout():
    cookie, _ = getauthcookie()
    if cookie:
        delcookie(cookie)
    return "You have been logged out"


def checkotp(user, otp):
    unverifiedkey = "unverified_{}".format(user.username)
    if user.otp:
        otphash = user.otp
    else:
        otphash = r.get(unverifiedkey)
        if not otphash:
            return None
    totp = pyotp.TOTP(otphash)
    verified = totp.verify(otp, valid_window=2)
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
        key = "cookie_{}".format(cookie)
        username = r.get(key)
        if username is not None:
            r.expire(key, AUTHED_TIMEOUT)
            return cookie, username
    return None, None


def setauthcookie(cookie, username):
    key = "cookie_{}".format(cookie)
    r.set(key, username)
    r.expire(key, AUTHED_TIMEOUT)


def gencookie():
    newcookie = secrets.token_urlsafe()
    key = "cookie_{}".format(newcookie)
    r.set(key, "")
    r.expire(key, UNAUTH_TIMEOUT)
    return newcookie


def delcookie(cookie):
    key = "cookie_{}".format(cookie)
    r.delete(key)


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
        level = ADMIN_LEVEL
    else:
        level = NORMAL_LEVEL
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


def deleteuser(username):
    user = WebUser.query.filter_by(username=username.lower()).first()
    db.session.delete(user)
    db.session.commit()


def updateuserlevel(username, level):
    user = WebUser.query.filter_by(username=username.lower()).first()
    user.level = level
    db.session.commit()


def resetuserpassword(username, clearpassword):
    user = WebUser.query.filter_by(username=username.lower()).first()
    user.password = crypt.crypt(clearpassword, crypt.mksalt())
    db.session.commit()


def resetusertoken(username):
    user = WebUser.query.filter_by(username=username.lower()).first()
    user.otp = None
    db.session.commit()


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

    db.create_all()

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--adduser", action="store_true")
    parser.add_argument("-r", "--resetpassword", action="store_true")
    parser.add_argument("-t", "--resettoken", action="store_true")
    parser.add_argument(
        "--debug", action="store_true", help="Run flask in debug mode for development."
    )
    args = parser.parse_args()
    if args.adduser:
        username = input("Username: ")
        password = promptpassword()
        addlogin(username, password, admin=True)
    elif args.resetpassword:
        username = input("Username: ")
        password = promptpassword()
        resetuserpassword(username, password)
    elif args.resettoken:
        username = input("Username: ")
        resetusertoken(username)
    else:
        app.run(host="0.0.0.0", port=LISTEN_PORT, debug=args.debug)


def log(msg):
    sys.stderr.write("{}\n".format(msg))
    sys.stderr.flush()


if __name__ == "__main__":
    main()
