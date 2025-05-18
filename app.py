from flask import Flask, request, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
DATABASE = 'database.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            otp_secret TEXT
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = generate_password_hash(data['password'])

    otp_secret = pyotp.random_base32()

    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, otp_secret) VALUES (?, ?, ?)', (username, password, otp_secret))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409

    return jsonify({'message': 'User registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    otp_code = data.get('otp')  # optional

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT password, otp_secret FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()

    if not result:
        return jsonify({'error': 'Invalid username or password'}), 401

    hashed_password, otp_secret = result

    if not check_password_hash(hashed_password, password):
        return jsonify({'error': 'Invalid username or password'}), 401

    if otp_code:
        totp = pyotp.TOTP(otp_secret)
        if not totp.verify(otp_code):
            return jsonify({'error': 'Invalid 2FA code'}), 401
        return jsonify({'message': 'Login success with 2FA!'})
    else:
        return jsonify({'message': 'Password correct, please enter your 2FA code'})

@app.route('/qrcode/<username>')
def get_qrcode(username):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT otp_secret FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()

    if not result:
        return jsonify({'error': 'User not found'}), 404

    otp_secret = result[0]
    uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="My2FAApp")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode()

    return render_template('qrcode.html', img_data=img_base64)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
