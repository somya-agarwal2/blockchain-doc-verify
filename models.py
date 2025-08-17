# models.py

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
from datetime import datetime

from flask_login import UserMixin


class Issuer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org = db.Column(db.String(100), nullable=False)
    org_type = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)  # make nullable if wallet login only
    proof_file = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')
    approved = db.Column(db.Boolean, default=False)



class IssuedDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    issuer_email = db.Column(db.String(100))
    user_name = db.Column(db.String(100))
    user_email = db.Column(db.String(100))
    file_name = db.Column(db.String(100))       # Human-readable document title (e.g., "Marksheet")
    filename = db.Column(db.String(100))        # ✅ Actual filename saved in "uploads/" (e.g., "abc123.pdf")
    file_hash = db.Column(db.String(256))
    issued_on = db.Column(db.DateTime)
    qr_code_path = db.Column(db.String(200))    # QR image path


class User(db.Model, UserMixin):  # ✅ Inherit from UserMixin
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    wallet_address = db.Column(db.String(255), unique=True, nullable=True)


class WalletNonce(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(255), unique=True, nullable=False)
    nonce = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<WalletNonce {self.address} - {self.nonce}>"

