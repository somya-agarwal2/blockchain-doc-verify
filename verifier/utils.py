# verifier/utils.py
# verifier/utils.py
import io
import qrcode
from flask import url_for, current_app, send_file

def generate_qr(document_id):
    # Generate the full verification URL
    with current_app.app_context():
        verification_url = url_for('verifier', _external=True) + f"?doc_id={document_id}"

    # Create the QR code
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(verification_url)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")

    # Save QR to in-memory bytes buffer instead of disk
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    # Return buffer so you can directly send it in a route
    return buf
