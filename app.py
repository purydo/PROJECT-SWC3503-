from flask import Flask, render_template, request, redirect, url_for, session, g 
import sqlite3 
import pyotp
import qrcode
import io
from base64 import b64encode
import bcrypt  # Import bcrypt for password hashing
from werkzeug.security import generate_password_hash, check_password_hash
import logging

app = Flask(__name__) 
app.secret_key = "supersecretkey"  # To manage sessions (required by Flask) 
 
DATABASE = 'members.db'

# Configure logging
logging.basicConfig(
    filename='gym_app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Helper function to hash passwords
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
 
# Simple user store for staff and members with hashed passwords
USERS = {
    "staff": {"password": generate_password_hash("staffpass"), "role": "staff", "mfa_secret": pyotp.random_base32()},
    "member": {"password": generate_password_hash("memberpass"), "role": "member", "mfa_secret": pyotp.random_base32()},
    "pakkarim": {"password": generate_password_hash("karim"), "role": "staff", "mfa_secret": pyotp.random_base32()}
} 
 
# Helper function to connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Audit logging helper
def log_audit(action, username=None, details=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (username, action, details, timestamp) VALUES (?, ?, ?, datetime('now'))",
        (username, action, details)
    )
    db.commit()
    logging.info(f"AUDIT: User={username}, Action={action}, Details={details}")

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close() 
 
# Login Route with MFA
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in USERS and check_password_hash(USERS[username]['password'], password):
            session['temp_user'] = username
            log_audit("LOGIN_ATTEMPT", username=username, details="Successful login")
            return redirect(url_for('mfa'))
        else:
            log_audit("LOGIN_ATTEMPT", username=username, details="Failed login attempt")
            return "Login Failed!"
    return render_template('login.html')

# MFA Verification Route
@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'temp_user' not in session:
        return redirect(url_for('login'))

    username = session['temp_user']
    user = USERS[username]
    totp = pyotp.TOTP(user['mfa_secret'])
    otp_url = totp.provisioning_uri(name=username, issuer_name="GymManagementApp")

    qr = qrcode.make(otp_url)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    qr_code = b64encode(img_io.getvalue()).decode('ascii')

    if request.method == 'POST':
        otp = request.form['otp']
        if totp.verify(otp):
            session['user'] = username
            session['role'] = user['role']
            session.pop('temp_user', None)
            log_audit("MFA_VERIFIED", username=username, details="MFA passed successfully")
            return redirect(url_for('dashboard'))
        else:
            log_audit("MFA_VERIFIED", username=username, details="Invalid MFA attempt")
            return "Invalid OTP! Please try again."

    return render_template('mfa.html', qr_code=qr_code)

# Route to Generate QR Code for Google Authenticator
@app.route('/mfa_setup')
def mfa_setup():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']
    user = USERS[username]

    # Generate a QR code for the user to scan
    totp = pyotp.TOTP(user['mfa_secret'])
    otp_url = totp.provisioning_uri(name=username, issuer_name="GymManagementApp")

    # Generate QR code image
    qr = qrcode.make(otp_url)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    qr_code = b64encode(img_io.getvalue()).decode('ascii')

    return render_template('mfa_setup.html', qr_code=qr_code)

def query_db(query, args=(), one=False): 
    cur = get_db().execute(query, args) 
    rv = cur.fetchall() 
    cur.close() 
    return (rv[0] if rv else None) if one else rv 
 
@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY, 
                    name TEXT NOT NULL, 
                    membership_status TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY, 
                    class_name TEXT NOT NULL, 
                    class_time TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER, 
                    class_id INTEGER, 
                    FOREIGN KEY (member_id) REFERENCES members (id), 
                    FOREIGN KEY (class_id) REFERENCES classes (id))''')
    db.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY, 
                    username TEXT, 
                    action TEXT NOT NULL, 
                    details TEXT, 
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    db.commit()

# Other Routes Remain Unchanged
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    username = session['user']
    return render_template('dashboard.html', username=username) 
 
# Member Management Routes 
@app.route('/add_member', methods=['GET', 'POST']) 
def add_member(): 
    if 'user' not in session or session['role'] != 'staff': 
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name'] 
        status = request.form['status'] 
        db = get_db() 
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status)) 
        db.commit() 
        return redirect(url_for('view_members'))
    
    return render_template('add_member.html')

#veiw specific member class 
@app.route('/member/<int:member_id>/classes') 
def member_classes(member_id): 
    if 'user' not in session: 
        return redirect(url_for('login')) 
     
    # Get member classes 
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], 
one=True) 
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c " 
                        "JOIN member_classes mc ON c.id = mc.class_id " 
                        "WHERE mc.member_id = ?", [member_id])
    
    return render_template('member_classes.html', member=member, 
classes=classes)

#register class 
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST']) 
def register_class(member_id): 
    if 'user' not in session or session['role'] != 'staff': 
        return redirect(url_for('login')) 
 
    classes = query_db("SELECT * FROM classes")  # Get all available classes 
    if request.method == 'POST': 
        class_id = request.form['class_id'] 
        db = get_db() 
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id)) 
        db.commit() 
        return redirect(url_for('member_classes', member_id=member_id)) 
     
    return render_template('register_class.html', member_id=member_id, 
classes=classes)

#view users 
@app.route('/view_members') 
def view_members(): 
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    members = query_db("SELECT * FROM members") 
    return render_template('view_members.html', members=members)

# New Route for Registering a Member 
@app.route('/register_member', methods=['GET', 'POST']) 
def register_member(): 
    if 'user' not in session or session['role'] != 'staff': 
        return redirect(url_for('login')) 
     
    if request.method == 'POST': 
        name = request.form['name'] 
        status = request.form['status'] 
        db = get_db() 
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status)) 
        db.commit() 
        return redirect(url_for('view_members')) 
     
    return render_template('register_member.html') 
 
# Class Scheduling Routes 
@app.route('/add_class', methods=['GET', 'POST']) 
def add_class(): 
    if 'user' not in session or session['role'] != 'staff': 
        return redirect(url_for('login')) 
     
    if request.method == 'POST': 
        class_name = request.form['class_name'] 
        class_time = request.form['class_time'] 
        db = get_db() 
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time)) 
        db.commit() 
        return redirect(url_for('view_classes')) 
     
    return render_template('add_class.html')

@app.route('/view_classes') 
def view_classes(): 
    if 'user' not in session: 
        return redirect(url_for('login')) 
     
    classes = query_db("SELECT * FROM classes") 
    return render_template('view_classes.html', classes=classes) 
 
#deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    db = get_db()
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    if member:
        db.execute("DELETE FROM members WHERE id = ?", [member_id])
        db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
        db.commit()
        log_audit("DELETE_MEMBER", username=session['user'], details=f"Deleted member {member['name']} (ID: {member_id})")
    return redirect(url_for('view_members'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)