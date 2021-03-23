#!/usr/bin/env python3

import flask
from flask import request
from flask import Response
from flask_sqlalchemy import SQLAlchemy
import pyotp
import qrcode
import argparse
import crypt
import getpass
import secrets
import base64
from io import BytesIO
import time
import redis
import json
import logging
import ipaddress
import requests

from auth import config

COOKIE_BASE_NAME = "magicproxyauth-"
AUTHFORM = "authform.jinja"

# The expiry time of cookies set with out authenticating
UNAUTH_TIMEOUT = 900
# The expiry time of an inactive cookie, cache updated every check
AUTHED_TIMEOUT = 365 * 24 * 3600  # One year days
authdcookies = set()

log = logging.getLogger(__name__)

r = redis.Redis(
    host=config.getconf("redis_host", default="redis"), decode_responses=True
)

RECAPTCHA_SITE_KEY = config.getconf("recaptcha_site_key")
RECAPTCHA_SECRET_KEY = config.getconf("recaptcha_secret_key")

HOME_PATH = config.getconf("home_path", "/")

app = flask.Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = config.getconf("db_uri", raiseerror=True)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

ADMIN_LEVEL = 100
NORMAL_LEVEL = 0

CAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
OTP_RECAPTCHA = "recaptcha"


class FixedLocationResponse(Response):
    autocorrect_location_header = False


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
error("Verify Authy Code");
"""


@app.route("/", defaults={"path": ""}, methods=["GET"])
@app.route("/<path:path>", methods=["GET"])
def index(path):
    # First check if the IP is whitelisted
    srcip = request.headers.get("X-Forwarded-For")
    if srcip and TRUSTED_NETWORKS:
        srcip = ipaddress.ip_address(srcip)
        for trustednet in TRUSTED_NETWORKS:
            if srcip in trustednet:
                return "Trusted_Net"

    x_username = request.headers.get("X-set-username")
    x_password = request.headers.get("X-set-password")
    x_otp = request.headers.get("X-set-otp")
    recaptcha_response = request.headers.get("X-set-recaptcha")
    if (
        x_username is not None
        and x_password is not None
        and (x_otp is not None or recaptcha_response is not None)
    ):
        return newlogin(x_username, x_password, x_otp, recaptcha_response)

    cookie, username = getauthcookie()
    if username:
        # Check the user is still real
        user = WebUser.query.filter_by(username=username).first()
        if user:
            if (
                request.headers.get("Host") in MY_DOMAINS
                or request.headers.get("X-Forwarded-Host") in MY_DOMAINS
            ):
                return """
                <html><head><meta http-equiv="Refresh" content="0; url='/magicauth/users/self'" />
                </head><body>Redirecting...</body></html>"""
                # return flask.redirect(
                #     "/magicauth/users/self", code=302, Response=FixedLocationResponse
                # )

            resp = flask.make_response("Auth {}".format(user.username))
            resp.headers["x-forwardauth-name"] = user.username
            return resp
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
                except Exception:
                    username, password = (None, None)
                if checkbasicauthlogin(username, password):
                    return "Auth"

    resp = flask.make_response(
        flask.render_template(AUTHFORM, recaptchasitekey=RECAPTCHA_SITE_KEY)
    )
    if cookie is None:
        setcookie(resp)
    return resp, 401


@app.route("/", defaults={"path": ""}, methods=["POST"])
@app.route("/<path:path>", methods=["POST"])
def submit(**path):
    srcip = request.headers.get("X-Forwarded-For", "").split(",")[0]
    username = request.headers.get("X-set-username")
    password = request.headers.get("X-set-password")
    otp = request.headers.get("X-set-otp")
    recaptcha_response = request.headers.get("X-set-recaptcha")
    return newlogin(username, password, otp, recaptcha_response, srcip)


def newlogin(username, password, otp, recaptcha_response, srcip=None):
    cookie, _ = getauthcookie()

    def loginok(user):
        setauthcookie(cookie, user.username)
        return "location.reload();", 401

    def error(msg):
        resp = flask.make_response(f"error({json.dumps(msg)});")
        setcookie(resp)
        return resp, 401

    if username:
        username = username.lower()

    if cookie:
        if RECAPTCHA_SITE_KEY and not validatecaptcha(recaptcha_response, srcip):
            return error("Invalid reCAPTCHA")
        user = checklogin(username, password)
        if user:
            otpcheck = checkotp(user, otp)
            if otpcheck is None:
                # Username and password is OK, but we need to create a OTP for them
                # or login via recaptcha
                if RECAPTCHA_SITE_KEY and user.otp == OTP_RECAPTCHA:
                    # This user can login using recaptcha only
                    return loginok(user)
                else:
                    otpuri = addotp(user)
                    img = qrcode.make(otpuri)
                    buf = BytesIO()
                    img.save(buf, format="PNG")
                    img_str = base64.b64encode(buf.getvalue()).decode()
                    return OTP_TEMPLATE.format(img_str), 401

            elif otpcheck is True:
                return loginok(user)
            else:
                time.sleep(1)
    else:
        time.sleep(1)
        return error("Wrong username/password or cookie not set")

    return error("Wrong username, password or code")


def setcookie(resp):
    authcookie = gencookie()
    resp.set_cookie(COOKIE_NAME, authcookie, domain=COOKIE_DOMAIN, max_age=2147483647)


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
        return flask.render_template(
            "users.html", activeuser=json.dumps(user.username), homepath=HOME_PATH
        )
    elif request.method == "POST":
        content = request.json
        ret = {"ok": False}
        try:
            if content.get("action") == "getusers":
                data = []
                for user in WebUser.query.order_by(WebUser.username).all():
                    otp = False
                    recaptcha = False
                    if user.otp:
                        if user.otp == OTP_RECAPTCHA:
                            recaptcha = True
                        else:
                            otp = True
                    data.append(
                        {
                            "username": user.username,
                            "level": user.level,
                            "tokenset": otp,
                            "allowrecaptcha": recaptcha,
                        }
                    )
                ret["users"] = data
                ret["ok"] = True

            elif content.get("action") == "adduser":
                password = secrets.token_urlsafe()[:8]
                addlogin(
                    content["username"],
                    password,
                    content["level"] == ADMIN_LEVEL,
                    content["allowrecaptcha"],
                )
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
    user = WebUser.query.filter_by(username=username).first()
    admin = user.level >= ADMIN_LEVEL
    if request.method == "GET":
        return flask.render_template(
            "self.html", activeuser=username, admin=admin, homepath=HOME_PATH
        )
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
    resp = flask.make_response("You have been logged out")
    if cookie:
        delcookie(cookie)
        resp.set_cookie(
            COOKIE_NAME, "", domain=COOKIE_DOMAIN, max_age=0, secure=COOKIE_SECURE
        )
    return resp


@app.route("/crash", methods=["GET", "POST"])
def crash():
    x = 0 / 0
    return str(x)


def checkotp(user, otp):
    unverifiedkey = "unverified_{}".format(user.username)
    if user.otp:
        otphash = user.otp
    else:
        otphash = r.get(unverifiedkey)
        if not otphash:
            return None
    totp = pyotp.TOTP(otphash)
    try:
        verified = totp.verify(otp, valid_window=2)
    except:
        return None
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
    cookie = request.cookies.get(COOKIE_NAME)
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


def addlogin(username, password, admin=False, allowrecaptcha=False):
    username = username.lower()
    passwordhash = crypt.crypt(password, crypt.mksalt())
    if admin:
        level = ADMIN_LEVEL
    else:
        level = NORMAL_LEVEL
    if allowrecaptcha:
        otp = OTP_RECAPTCHA
    else:
        otp = None
    user = WebUser(username=username, password=passwordhash, level=level, otp=otp)
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
    global COOKIE_NAME, COOKIE_DOMAIN, COOKIE_SECURE, LISTEN_PORT, MY_DOMAINS, TRUSTED_NETWORKS
    COOKIE_DOMAIN = config.getconf("cookie_domain")
    COOKIE_NAME = COOKIE_BASE_NAME + str(COOKIE_DOMAIN)
    COOKIE_SECURE = config.getbool("cookie_secure")
    mydomainsstr = config.getconf("my_domains")
    MY_DOMAINS = []
    if mydomainsstr is not None:
        domains = mydomainsstr.split(",")
        for domain in domains:
            domain = domain.strip()
            if domain:
                MY_DOMAINS.append(domain)
    trustednetsstr = config.getconf("trusted_nets")
    TRUSTED_NETWORKS = []
    if trustednetsstr is not None:
        nets = trustednetsstr.split(",")
        for net in nets:
            net = net.strip()
            if net:
                TRUSTED_NETWORKS.append(ipaddress.ip_network(net, strict=False))
    LISTEN_PORT = config.getint("listen_port", 80)


def validatecaptcha(response, srcip=None):
    args = {"secret": RECAPTCHA_SECRET_KEY, "response": response}
    if srcip:
        args["remoteip"] = srcip
    r = requests.post(CAPTCHA_VERIFY_URL, args)
    response = r.json()
    if response["success"]:
        return True
    print("Failed Verification:", response)
    return False


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


if __name__ == "__main__":
    main()
