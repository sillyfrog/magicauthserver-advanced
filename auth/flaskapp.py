from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os


app = Flask(__name__)
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "postgresql+psycopg2://postgres:secret@postgres/users"


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
