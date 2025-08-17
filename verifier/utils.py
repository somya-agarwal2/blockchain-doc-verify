# verifier/utils.py
import qrcode
import os
from flask import url_for
from werkzeug.utils import secure_filename


def generate_qr(document_id):
    from flask import url_for, current_app

    # Generate the full verification URL
    with current_app.app_context():
        verification_url = url_for('verifier', _external=True) + f"?doc_id={document_id}"

    # Create the QR code
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(verification_url)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")

    # Save the QR code image to a file
    qr_folder = os.path.join('static', 'qr_codes')
    os.makedirs(qr_folder, exist_ok=True)
    qr_path = os.path.join(qr_folder, f"{document_id}.png")
    img.save(qr_path)

    # Return relative path to use in templates
    return f"qr_codes/{document_id}.png"
