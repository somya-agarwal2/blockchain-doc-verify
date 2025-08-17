from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import os
from datetime import datetime
from werkzeug.utils import secure_filename
import hashlib
from models import db, Issuer, IssuedDocument, User
from verifier.hash_util import hash_file
from verifier.blockchain import Blockchain
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from sqlalchemy import or_
from verifier.watermark_util import watermark_image, watermark_pdf, generate_qr_code
# app.py - updated route
from flask import current_app  # near other imports if not already imported
from dotenv import load_dotenv
load_dotenv()
from models import db, WalletNonce
# app.py (top of file imports)




# Initialize Web3 (you can connect to Infura/Alchemy or just use a dummy provider)


from datetime import  timedelta

from sqlalchemy import func





from eth_account.messages import encode_defunct
from web3 import Web3
# or Issuer if needed

from eth_account import Account
# In-memory storage for simplicity; in production use DB
wallet_nonces = {}

import secrets
from flask import jsonify
from eth_account.messages import encode_defunct
from eth_account import Account

w3 = Web3()




# Store nonce temporarily (in production use DB or cache)
nonces = {}
# Initialize blockchain
blockchain = Blockchain()

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Upload folders
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

PROOF_UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'proof_uploads')
app.config['PROOF_UPLOAD_FOLDER'] = PROOF_UPLOAD_FOLDER

app.config['QR_FOLDER'] = os.path.join(app.static_folder, 'qr_codes')
os.makedirs(app.config['QR_FOLDER'], exist_ok=True)



# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROOF_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(app.config['QR_FOLDER'], exist_ok=True)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Init DB and migrate
db.init_app(app)
migrate = Migrate(app, db)

# Setup LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    faqs = [
        {
            "question": "How does the verification actually work?",
            "answer": "We compute a SHA-256 hash of the uploaded file and compare it with the immutable hash stored on-chain by the issuer. If they match, the document is verified."
        },
        {
            "question": "Is my document stored on the blockchain?",
            "answer": "No—only the cryptographic hash and minimal metadata are recorded. The original file never leaves your device and is not retrievable from the chain."
        },
        {
            "question": "What file types are supported?",
            "answer": "PDFs, images (PNG/JPG), and common document formats. Anything that can be hashed can be verified."
        },
        {
            "question": "Can anyone become an issuer?",
            "answer": "Organizations apply through the Issuer portal. After admin approval, they can issue verified records immediately."
        }
    ]
    return render_template("home.html", faqs=faqs)
    return render_template('home.html')


@app.route('/issuer')
def issuer_redirect():
    return redirect(url_for('issuer_login'))



@app.route('/issuer/signup', methods=['GET', 'POST'])
def issuer_signup():
    if request.method == 'POST':
        org = request.form['org']
        org_type = request.form['org_type']
        email = request.form['email']
        password = request.form['password']
        proof_file = request.files['proof_file']

        existing = Issuer.query.filter_by(email=email).first()
        if existing:
            if existing.status == 'pending':
                flash('Issuer already registered and pending approval.')
            elif existing.status == 'approved':
                flash('An issuer with this email is already approved.')
            else:
                flash('An issuer with this email already exists.')
            return redirect(url_for('issuer_signup'))

        # Save proof file
        filename = secure_filename(proof_file.filename)
        filepath = os.path.join(app.config['PROOF_UPLOAD_FOLDER'], filename)
        proof_file.save(filepath)

        # Save to DB
        hashed_pw = generate_password_hash(password)
        new_issuer = Issuer(
            org=org,
            org_type=org_type,
            email=email,
            password_hash=hashed_pw,
            proof_file=filename,
            status='pending',      # Required for tracking
            approved=False         # Explicitly unapproved
        )
        db.session.add(new_issuer)
        db.session.commit()

        flash('Signup submitted. Awaiting admin approval.')
        return redirect(url_for('issuer_login'))

    return render_template('issuer_signup.html')


@app.route('/issuer/login', methods=['GET', 'POST'])
def issuer_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        issuer = Issuer.query.filter_by(email=email).first()
        if not issuer:
            flash('Issuer not found.')
            return redirect(url_for('issuer_login'))

        if issuer.status != 'approved':
            flash(f'Account is not approved yet (Status: {issuer.status})')
            return redirect(url_for('issuer_login'))

        if check_password_hash(issuer.password_hash, password):
            session['issuer_email'] = email
            flash('Login successful.')
            return redirect(url_for('issuer_dashboard'))
        else:
            flash('Incorrect password.')
            return redirect(url_for('issuer_login'))

    return render_template('issuer_login.html')


@app.route('/issuer/dashboard')
def issuer_dashboard():
    if 'issuer_email' not in session:
        return redirect(url_for('issuer_login'))

    # Fetch documents for the logged-in issuer
    documents = IssuedDocument.query.filter_by(issuer_email=session['issuer_email']).all()
    return render_template('issuer_dashboard.html', documents=documents)


@app.route('/issuer/logout')
def issuer_logout():
    session.pop('issuer_email', None)
    flash('Logged out successfully.')
    return redirect(url_for('issuer_login'))




@app.route('/issuer/issue', methods=['POST'])
def issue_document():
    if 'issuer_email' not in session:
        return redirect(url_for('issuer_login'))

    user_name = request.form['user_name']
    user_email = request.form['user_email']
    file_name = request.form['file_name']
    file = request.files['document']

    if not file:
        flash("No document uploaded.")
        return redirect(url_for('issuer_dashboard'))

    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Save uploaded file
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Calculate file hash & create DB record
    file_hash = calculate_file_hash(filepath)
    new_doc = IssuedDocument(
        issuer_email=session['issuer_email'],
        user_name=user_name,
        user_email=user_email,
        file_name=file_name,
        filename=filename,
        file_hash=file_hash,
        issued_on=datetime.utcnow()
    )
    db.session.add(new_doc)
    db.session.flush()  # Ensure new_doc.id is available (no commit yet)

    # Add to blockchain
    tx_id = blockchain.add_block({
        "file_hash": file_hash,
        "issuer": session['issuer_email']
    })

    # Ensure QR folder exists inside Flask static
    qr_folder_path = os.path.join(app.static_folder, "qr_codes")
    os.makedirs(qr_folder_path, exist_ok=True)

    # Build the verification URL (use absolute URL so QR links work externally)
    qr_data = url_for('verify_document', doc_id=new_doc.id, _external=True)

    # Generate QR: get both disk path and web relative path
    qr_filename = f"{new_doc.id}.png"
    qr_disk_path, qr_web_rel = generate_qr_code(qr_data, qr_filename, folder=qr_folder_path)

    # Save web relative path (NOT starting with /static) so templates can use url_for
    new_doc.qr_code_path = qr_web_rel  # e.g. "qr_codes/12.png"

    # Watermark text
    watermark_text = f"Issued by {session['issuer_email']} | Blockchain TX: {tx_id}"

    # Apply watermark depending on file type
    if filename.lower().endswith(".pdf"):
        watermarked_path = filepath.replace(".pdf", "_wm.pdf")
        # pass disk path (filesystem) to watermark_pdf so it can open the image
        watermark_pdf(input_path=filepath, output_path=watermarked_path, qr_image_path=qr_disk_path)
        # replace original file with watermarked file
        try:
            os.remove(filepath)
        except PermissionError:
            import time
            time.sleep(0.5)
            os.remove(filepath)
        os.rename(watermarked_path, filepath)

    elif filename.lower().endswith((".png", ".jpg", ".jpeg")):
        # watermark_image uses qr data to generate QR into the image; optional to pass qr_disk_path
        watermark_image(input_path=filepath, output_path=filepath, watermark_text=watermark_text, qr_data=qr_data)

    # Final commit saving qr_code_path to DB
    db.session.commit()

    flash('✅ Document issued with watermark & QR code!')
    return redirect(url_for('issuer_dashboard'))



@app.route('/blockchain')
def view_blockchain():
    blocks = [{
        "index": block.index,
        "timestamp": block.timestamp,
        "data": block.data,
        "hash": block.hash,
        "previous_hash": block.previous_hash
    } for block in blockchain.chain]

    return render_template("blockchain_view.html", blocks=blocks)


@app.route('/verifier', methods=['GET', 'POST'])
def verifier():
    if request.method == 'POST':
        file = request.files['document']
        if not file:
            flash("No file uploaded.")
            return redirect(url_for('verifier'))

        # Save temporarily
        filename = secure_filename(file.filename)
        temp_folder = "temp_uploads"
        os.makedirs(temp_folder, exist_ok=True)
        temp_path = os.path.join(temp_folder, filename)
        file.save(temp_path)

        # Hash the uploaded file
        file_hash = hash_file(temp_path)

        # Check in database
        issued = IssuedDocument.query.filter_by(file_hash=file_hash).first()

        if issued:
            result = {
                "verified": True,
                "file_name": issued.file_name,
                "user_name": issued.user_name,
                "user_email": issued.user_email,
                "issuer_email": issued.issuer_email,
                "issued_on": issued.issued_on.strftime('%Y-%m-%d %H:%M:%S')
            }
        else:
            result = {"verified": False}

        os.remove(temp_path)  # Clean up
        return render_template("verifier_result.html", result=result)

    return render_template("verifier_upload.html")


@app.route('/user', methods=['GET', 'POST'])
def user_portal():
    if request.method == 'POST':
        email = request.form['email']
        # Fetch all documents issued to this email
        documents = IssuedDocument.query.filter_by(user_email=email).all()
        return render_template('user_documents.html', documents=documents, user_email=email)

    return render_template('user_login.html')


@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    # Detect if request is JSON
    is_json = request.is_json
    data = request.get_json(silent=True) if is_json else request.form

    if request.method == 'POST':
        name = (data.get('name') or '').strip()
        email = (data.get('email') or '').strip().lower()
        password = (data.get('password') or '').strip()
        confirm_password = (data.get('confirm_password') or '').strip()
        wallet_address = (data.get('wallet_address') or '').strip().lower()

        # Check passwords
        if password != confirm_password:
            msg = "Passwords do not match."
            if is_json:
                return jsonify({"success": False, "message": msg}), 400
            flash(msg, "danger")
            return redirect(url_for('user_signup'))

        # Check if email exists
        if User.query.filter(func.lower(User.email) == email).first():
            msg = "Email already registered."
            if is_json:
                return jsonify({"success": False, "message": msg}), 400
            flash(msg, "danger")
            return redirect(url_for('user_signup'))

        # Check if wallet exists
        if wallet_address and User.query.filter(func.lower(User.wallet_address) == wallet_address).first():
            msg = "Wallet address already registered."
            if is_json:
                return jsonify({"success": False, "message": msg}), 400
            flash(msg, "danger")
            return redirect(url_for('user_signup'))

        # Hash password
        hashed_pw = generate_password_hash(password)

        # Create user
        user = User(
            name=name,
            email=email,
            password_hash=hashed_pw,
            wallet_address=wallet_address if wallet_address else None
        )
        db.session.add(user)
        db.session.commit()

        msg = "Signup successful! You can now log in."
        if is_json:
            return jsonify({"success": True, "message": msg})
        flash(msg, "success")
        return redirect(url_for('user_login'))

    # GET request → render template
    return render_template('user_signup.html')





@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        user = User.query.filter(func.lower(User.email) == email).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('user_login'))

        # ✅ Log in the user
        login_user(user)
        flash('Logged in successfully!', 'success')

        # Optional: Warn if wallet not linked
        if not user.wallet_address or user.wallet_address.strip() == "":
            return redirect(url_for('link_wallet'))

        return redirect(url_for('user_dashboard'))

    return render_template('user_login.html')






@app.route('/user/dashboard')
@login_required
def user_dashboard():
    user = current_user
    # Show all documents for the logged-in user
    user_documents = IssuedDocument.query.filter_by(user_email=user.email) \
                                         .order_by(IssuedDocument.issued_on.desc()).all()
    return render_template('user_dashboard.html', documents=user_documents, user=user)



@app.route('/user/logout')
@login_required
def user_logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('user_login'))


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        admin_username = os.getenv("ADMIN_USERNAME")
        admin_password = os.getenv("ADMIN_PASSWORD")

        if username == admin_username and password == admin_password:
            session['admin_logged_in'] = True
            flash('Admin logged in.')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.')
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    # Show all issuers whose approval is pending
    pending_issuers = Issuer.query.filter(
        or_(Issuer.approved == False, Issuer.approved == None)
    ).all()

    wallet_requests = { 
        "user@example.com": {"wallet": "0x123..."}  # example
    }

    return render_template(
        'admin_dashboard.html',
        issuers=pending_issuers,
        requests=wallet_requests
    )


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('admin_login'))


@app.route('/admin/approve', methods=['POST'])
def admin_approve():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    issuer_id = request.form.get('issuer_id')
    issuer = Issuer.query.get_or_404(issuer_id)
    issuer.status = 'approved'
    db.session.commit()
    flash(f"Issuer {issuer.org} approved.")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/reject', methods=['POST'])
def admin_reject():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))

    issuer_id = request.form.get('issuer_id')
    issuer = Issuer.query.get_or_404(issuer_id)
    issuer.status = 'rejected'
    db.session.commit()
    flash(f"Issuer {issuer.org} rejected.")
    return redirect(url_for('admin_dashboard'))

@app.route('/user/approve/<int:doc_id>', methods=['POST'])
@login_required
def approve_document(doc_id):
    document = IssuedDocument.query.get(doc_id)
    if document:
        document.is_approved = True
        db.session.commit()
    return redirect(url_for('user_dashboard'))



@app.route('/verify/<int:doc_id>')
def verify_document(doc_id):
    doc = IssuedDocument.query.get_or_404(doc_id)
    return render_template('verify_document.html', doc=doc)


def calculate_file_hash(filepath):
    """Utility to calculate SHA-256 hash of a file."""
    BUF_SIZE = 65536  # 64kb chunks
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()





# helper: checksum normalize
def checksum_addr(addr: str) -> str:
    """Normalize Ethereum address for DB storage and comparison."""
    return addr.lower() if addr else None

# -------- Nonce endpoint --------

@app.route('/auth/nonce')
def auth_nonce():
    address = request.args.get('address') or request.args.get('wallet_address')
    if not address:
        return jsonify({'error': 'address (or wallet_address) is required'}), 400

    nonce = generate_nonce_for_address(address)
    return jsonify({'nonce': nonce})



import secrets

def generate_nonce_for_address(address):
    existing = WalletNonce.query.filter_by(address=address).first()
    if existing:
        # update existing nonce
        existing.nonce = secrets.token_hex(16)
        db.session.commit()
        return existing.nonce
    else:
        # create new record
        nonce = secrets.token_hex(16)
        new_entry = WalletNonce(address=address, nonce=nonce)
        db.session.add(new_entry)
        db.session.commit()
        return nonce


# -------- Wallet login endpoint --------
@app.route('/auth/login', methods=['POST'])
def auth_login():
    data = request.get_json(silent=True) or {}
    address = checksum_addr(data.get('address', '').strip())
    signature = data.get('signature', '').strip()

    if not address or not signature:
        return jsonify({'success': False, 'message': 'Missing address or signature'}), 400

    # find nonce for address
    wn = WalletNonce.query.filter_by(address=address).first()
    if not wn:
        return jsonify({'success': False, 'message': 'Nonce not found for address. Start over.'}), 400

    # optional: expire nonce after 5 minutes
    if wn.created_at < datetime.utcnow() - timedelta(minutes=5):
        db.session.delete(wn)
        db.session.commit()
        return jsonify({'success': False, 'message': 'Nonce expired. Please try again.'}), 400

    # recover address from signature
    try:
        msg = encode_defunct(text=wn.nonce)
        recovered = Account.recover_message(msg, signature=signature).lower()
    except Exception as e:
        return jsonify({'success': False, 'message': f'Invalid signature: {e}'}), 400

    if recovered != address:
        return jsonify({'success': False, 'message': 'Signature does not match address'}), 400

    # find user by wallet_address
    user = User.query.filter(func.lower(User.wallet_address) == address).first()
    if not user:
        # No user with this wallet → ask to sign up first
        return jsonify({'success': False, 'message': 'No user with this wallet. Please sign up and add this wallet first.'}), 404

    # ✅ log them in
    login_user(user)

    # consume nonce (one-time use)
    db.session.delete(wn)
    db.session.commit()

    return jsonify({'success': True})


import random, string
from flask import request, jsonify

@app.route('/user/get-nonce')
def get_nonce():
    wallet_address = request.args.get('wallet_address')
    if not wallet_address:
        return jsonify({"success": False, "message": "Missing wallet_address"}), 400

    # Generate a random nonce
    generated_nonce = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    # ✅ Remove old nonce if it exists
    existing = WalletNonce.query.filter_by(address=wallet_address).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()

    # Insert the new nonce
    new_nonce = WalletNonce(address=wallet_address, nonce=generated_nonce)
    db.session.add(new_nonce)
    db.session.commit()

    return jsonify({"success": True, "nonce": generated_nonce})



from flask_login import login_required, current_user



from flask_login import login_user

@app.route('/user/link-wallet', methods=['GET', 'POST'])
@login_required
def link_wallet():
    if request.method == 'GET':
        # Render the wallet linking page
        return render_template('link_wallet.html')

    # ----- POST logic: linking wallet -----
    # 1️⃣ Parse JSON safely
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "message": "Invalid JSON body"}), 400

    wallet_address = data.get("wallet_address")
    signature = data.get("signature")

    if not wallet_address or not signature:
        return jsonify({"success": False, "message": "Missing wallet_address or signature"}), 400

    if not current_user.is_authenticated:
        return jsonify({"success": False, "message": "User not logged in"}), 401

    # 2️⃣ Get latest nonce for this wallet
    nonce_entry = WalletNonce.query.filter_by(address=wallet_address) \
                    .order_by(WalletNonce.created_at.desc()).first()
    if not nonce_entry:
        return jsonify({"success": False, "message": "Nonce not found"}), 400

    # 3️⃣ Verify signature
    try:
        message = encode_defunct(text=nonce_entry.nonce)
        recovered_address = w3.eth.account.recover_message(message, signature=signature)
    except Exception as e:
        return jsonify({"success": False, "message": f"Signature verification failed: {str(e)}"}), 400

    if recovered_address.lower() != wallet_address.lower():
        return jsonify({"success": False, "message": "Signature does not match wallet"}), 400

    # 4️⃣ Check if wallet is already linked to another user
    existing_user = User.query.filter(User.wallet_address.ilike(wallet_address)).first()
    if existing_user and existing_user.id != current_user.id:
        return jsonify({"success": False, "message": "This wallet is already linked to another account"}), 400

    # 5️⃣ Link wallet & consume nonce in a single transaction
    try:
        current_user.wallet_address = wallet_address
        db.session.delete(nonce_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"DB error: {str(e)}"}), 500

    # 6️⃣ Log in user
    login_user(current_user)

    # 7️⃣ Return success with redirect URL
    return jsonify({
        "success": True,
        "message": "Wallet linked and logged in successfully",
        "redirect_url": url_for('user_dashboard')
    })






if __name__ == "__main__":
    app.run(debug=True)
