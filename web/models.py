from flask_login import UserMixin
from . import db

#class User(UserMixin,db.Model):
    # primary keys are required by SQLAlchemy
#    id = db.Column(db.Integer, primary_key=True)
#    email = db.Column(db.String(100), unique=True)
#    password = db.Column(db.String(100))
#    name = db.Column(db.String(1000))

class User(UserMixin):
    def __init__(self, dn, username, data):
        self.dn = dn
        self.username = username
        self.data = data

    def __repr__(self):
        return self.dn

    def get_id(self):
        return self.dn
