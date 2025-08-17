from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from reportlab.lib.units import inch
import qrcode
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
import tempfile
import os

import shutil



def generate_qr_code(data, filename="temp_qr.png", folder=None):
    """
    Generate QR code PNG and save to `folder`.
    Returns a tuple: (disk_path, web_rel_path)
      - disk_path: full filesystem path (e.g. /home/.../static/qr_codes/1.png)
      - web_rel_path: relative path to use with url_for('static', filename=...), e.g. 'qr_codes/1.png'
    """
    if folder is None:
        # make sure default uses Flask static folder when caller doesn't pass folder
        folder = os.path.join(os.getcwd(), "static", "qr_codes")

    os.makedirs(folder, exist_ok=True)

    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white").resize((200, 200))

    disk_path = os.path.join(folder, filename)
    img.save(disk_path)

    # web_rel_path for url_for('static', filename=web_rel_path)
    web_rel_path = os.path.join("qr_codes", filename).replace("\\", "/")
    return disk_path, web_rel_path



def watermark_pdf(input_path, output_path, watermark_text=None, qr_image_path=None, save_qr_path=None):
    if qr_image_path:
        qr_path = qr_image_path
    elif watermark_text:
        # Generate QR in temp dir
        temp_dir = tempfile.gettempdir()
        temp_qr_file = os.path.join(temp_dir, "temp_qr.png")
        generate_qr_code(watermark_text, filename="temp_qr.png", folder=temp_dir)
        
        if save_qr_path:
            os.makedirs(os.path.dirname(save_qr_path), exist_ok=True)
            shutil.copyfile(temp_qr_file, save_qr_path)
            qr_path = save_qr_path
        else:
            qr_path = temp_qr_file
    else:
        qr_path = None

    with open(input_path, "rb") as in_file:
        original_pdf = PdfReader(in_file)
        output_pdf = PdfWriter()

        for page in original_pdf.pages:
            packet = BytesIO()
            can = canvas.Canvas(packet, pagesize=letter)

            if qr_path and os.path.exists(qr_path):
                qr_img = ImageReader(qr_path)
                page_width = float(page.mediabox.width)
                page_height = float(page.mediabox.height)
                can.drawImage(qr_img, x=page_width - 120, y=20, width=100, height=100, mask='auto')

            can.save()
            packet.seek(0)
            watermark_pdf_obj = PdfReader(packet)

            page.merge_page(watermark_pdf_obj.pages[0])
            output_pdf.add_page(page)

        with open(output_path, "wb") as out_file:
            output_pdf.write(out_file)



def watermark_image(input_path, output_path, watermark_text, qr_data):
    """
    Add watermark text and QR code to an image (PNG/JPEG).
    """
    base_image = Image.open(input_path).convert("RGBA")

    # Create watermark layer
    watermark_layer = Image.new("RGBA", base_image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(watermark_layer)

    width, height = base_image.size

    # Load font
    try:
        font = ImageFont.truetype("arial.ttf", 20)
    except IOError:
        font = ImageFont.load_default()

    # Draw watermark text at bottom left
    text_pos = (10, height - 30)
    draw.text(text_pos, watermark_text, fill=(180, 180, 180, 150), font=font)

    # Generate QR code image in memory
    qr_img = qrcode.make(qr_data).convert("RGBA")
    qr_img = qr_img.resize((100, 100))

    # Paste QR code bottom right
    qr_pos = (width - qr_img.width - 10, height - qr_img.height - 10)
    watermark_layer.paste(qr_img, qr_pos, qr_img)

    # Composite watermark onto base image
    watermarked = Image.alpha_composite(base_image, watermark_layer)

    # Save result
    watermarked = watermarked.convert("RGB")  # Remove alpha for saving JPEG
    watermarked.save(output_path)


# Example usage:
if __name__ == "__main__":
    # If you want both the QR in PDF and a separate QR file
    watermark_pdf(
      "input.pdf",
      "output.pdf",
      watermark_text="https://example.com",
      save_qr_path="static/my_qr.png"
   )


    # For Image watermark
    watermark_image(
        input_path="input.jpg",
        output_path="watermarked.jpg",
        watermark_text="Confidential",
        qr_data="https://example.com"
    )
