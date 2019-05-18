#!/usr/bin/env python3

import flask
from flask import request
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

LOGINS_FILE = "proxylogins"
BASIC_AUTH_LOGINS_FILE = "basicauthlogins"
OTP_FILE = "otpkeys"
COOKIE = "magicproxyauth"
AUTHFORM = "authform.html"
LOGINS = {}
BASIC_AUTH_LOGINS = {}
OTPHASHES = {}

authdcookies = set()
unverifiedotp = {}


app = flask.Flask(__name__)

OTP_TEMPLATE = """
e = document.getElementById("forotp");
e.innerHTML="Scan this code in your Authy app:<br><img src='data:image/png;base64,{}'>";
error("Verify OTP Code");
"""


@app.route("/", defaults={"path": ""}, methods=["GET"])
@app.route("/<path:path>", methods=["GET"])
def index(path):
    authcookie = getauthcookie()
    if authcookie in authdcookies:
        return "Auth"

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
    if authcookie is None:
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
    authvalue = getauthcookie()

    if username:
        username = username.lower()

    if authvalue and checklogin(username, password):
        otpcheck = checkotp(username, otp)
        if otpcheck == None:
            # Username and password is OK, but we need to create a OTP for them
            otpuri = addotp(username)
            img = qrcode.make(otpuri)
            buf = BytesIO()
            img.save(buf, format="PNG")
            img_str = base64.b64encode(buf.getvalue()).decode()
            return OTP_TEMPLATE.format(img_str), 401

        elif otpcheck == True:
            authdcookies.add(authvalue)
            return "location.reload();", 401
        else:
            time.sleep(0.5)
            return "error('Wrong username, password or code');", 401
    else:
        time.sleep(1)
        return "error('Wrong username/password or cookie not set');", 401


def checkotp(username, otp):
    if username in OTPHASHES:
        otphash = OTPHASHES[username]
    elif username in unverifiedotp:
        otphash = unverifiedotp[username]
    else:
        return None
    totp = pyotp.TOTP(otphash)
    verified = totp.verify(otp, valid_window=1)
    if username in unverifiedotp:
        if verified:
            del unverifiedotp[username]
            OTPHASHES[username.lower()] = otphash
            saveotps()
        else:
            # We have an OTP code for this user, but the have not yet verified it.
            return None
    return verified


def addotp(username):
    if username in unverifiedotp:
        otphash = unverifiedotp[username]
    else:
        otphash = pyotp.random_base32()
        unverifiedotp[username] = otphash
    totp = pyotp.TOTP(otphash)
    return totp.provisioning_uri(username, COOKIE_DOMAIN)


def saveotps():
    savefile(OTPHASHES, OTP_FILE)


def getauthcookie():
    authvalue = request.cookies.get(COOKIE)
    if authvalue:
        if len(authvalue) < 24:
            authvalue = None
    return authvalue


def gencookie():
    return secrets.token_urlsafe()


def loadlogins(ignoreerrors=False):
    LOGINS.update(loadfile(LOGINS_FILE, ignoreerrors))
    BASIC_AUTH_LOGINS.update(loadfile(BASIC_AUTH_LOGINS_FILE, True))
    OTPHASHES.update(loadfile(OTP_FILE, True))


def loadfile(path, ignoreerrors=False):
    try:
        f = open(path)
    except Exception as e:
        if ignoreerrors:
            return {}
        else:
            log(("Error loading {} file: {}".format(path, e)))
            return None

    ret = {}
    for line in f:
        line = line.strip()
        parts = line.split()
        if len(parts) != 2:
            continue

        username, password = parts
        if len(username) < 3 or len(password) < 3:
            continue

        ret[username.lower()] = password
    return ret


def checklogin(username, password):
    if username.lower() in LOGINS:
        if LOGINS[username] == crypt.crypt(password, LOGINS[username]):
            return True
    return False


def checkbasicauthlogin(username, password):
    if not username or not password:
        return False
    if username.lower() in BASIC_AUTH_LOGINS:
        if BASIC_AUTH_LOGINS[username] == crypt.crypt(
            password, BASIC_AUTH_LOGINS[username]
        ):
            return True
    return False


def addlogin(username, password):
    loadlogins(ignoreerrors=True)
    LOGINS[username.lower()] = crypt.crypt(password, crypt.mksalt())
    savefile(LOGINS, LOGINS_FILE)


def addbasiclogin(username):

    loadlogins(ignoreerrors=True)
    password = secrets.token_urlsafe()
    print("New password for {}: {}".format(username, password))
    BASIC_AUTH_LOGINS[username.lower()] = crypt.crypt(password, crypt.mksalt())
    savefile(BASIC_AUTH_LOGINS, BASIC_AUTH_LOGINS_FILE)


def savefile(data, path):
    f = open(path, "w")
    for user, password in data.items():
        f.write("{}\t{}\n".format(user, password))
    f.close()


def promptpassword():
    while 1:
        password1 = getpass.getpass("Password: ")
        password2 = getpass.getpass("Re-enter Password: ")
        if password1 == password2:
            return password1
        print("Passwords don't match!")


def main():
    global COOKIE_DOMAIN, COOKIE_SECURE
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d",
        "--domain",
        help="Domain to use when setting the cookie, ideally your root domain. "
        'This can also be set using the "DOMAIN" environment variable.',
    )
    parser.add_argument("-p", "--port", type=int, help="Port to listen on, default 80")
    parser.add_argument("-a", "--adduser", action="store_true")
    parser.add_argument(
        "--addbasicuser", action="store_true", help="Add a user using basic auth"
    )
    parser.add_argument(
        "--nosecure",
        action="store_true",
        help="Do NOT set the secure flag on the cookie, used for development.",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Run flask in debug mode for development."
    )
    args = parser.parse_args()
    if not args.domain:
        if os.environ.get("DOMAIN"):
            args.domain = os.environ["DOMAIN"]
    if not args.port:
        if os.environ.get("PORT"):
            args.port = int(os.environ["PORT"])
        else:
            args.port = 80
    if args.nosecure:
        COOKIE_SECURE = False
    else:
        COOKIE_SECURE = True
    if args.adduser:
        username = input("Username: ")
        password = promptpassword()
        addlogin(username, password)
    elif args.addbasicuser:
        username = input("Username: ")
        addbasiclogin(username)
    elif args.domain:
        COOKIE_DOMAIN = args.domain
        loadlogins()
        app.run(host="0.0.0.0", port=args.port, debug=args.debug)
    else:
        log("Either -d or -a must be supplied or environment set!")
        sys.exit(1)


def log(msg):
    sys.stderr.write("{}\n".format(msg))
    sys.stderr.flush()


if __name__ == "__main__":
    main()
