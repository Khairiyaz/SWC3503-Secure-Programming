
from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re
#from flask import request, render_template, redirect, url_for, session
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "supersecretkey"  # To manage sessions (required by Flask)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)  # 15 minutes timeout

DATABASE = 'members.db'

# Simple user store for staff and members (no security library)
#USERS = {
#    "staff": {"password": "staffpass", "role": "staff"},
#   "member": {"password": "memberpass", "role": "member"},
#    "pakkarim": {"password": "karim", "role": "staff"}
#}

# Helper function to connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    # Set row_factory to sqlite3.Row so we can access columns by name
    cur = get_db()
    cur.row_factory = sqlite3.Row  # This enables access by column name
    cur = cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    membership_status TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                  )''')
    
    db.execute('''CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL
                )''')
    db.commit()

@app.before_request
def check_session_timeout():
    session_timeout = timedelta(minutes=1)
    now = datetime.utcnow()

    # Check for the last activity time in session
    last_activity = session.get('last_activity')

    if last_activity:
        time_diff = now - datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")
        if time_diff > session_timeout:
            session.pop('user', None)  # Expire the session if it exceeds the timeout
            return redirect(url_for('login'))  # Redirect to login page

    # Update the last activity time
    session['last_activity'] = now.strftime("%Y-%m-%d %H:%M:%S")

@app.route('/initialize_users')
def initialize_users():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))  # Ensure only staff can initialize users

    # Check if users are already in the database to avoid duplication
    db = get_db()
    existing_users = query_db("SELECT * FROM users")
    
    if existing_users:
        return "Users are already initialized!", 200  # No need to re-initialize

    # Predefined users to add
    users_to_add = [
        ("staff", generate_password_hash("staffpass"), "staff"),
        ("member", generate_password_hash("memberpass"), "member"),
        ("pakkarim", generate_password_hash("karim"), "staff")
    ]

    # Insert predefined users into the users table
    db.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", users_to_add)
    db.commit()

    return "Users initialized successfully!", 200



@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Server-Side Validation
        if not username or not password:
            return "Username and password are required."
        
        if len(username) < 3:  # Example of length validation for username
            return "Username must be at least 3 characters long."

        # Assuming the user table contains 'username' and 'password' columns
        user = query_db("SELECT * FROM users WHERE username = ?", [username], one=True)

        if user and check_password_hash(user['password'], password):  # Verifying the hashed password
            session['user'] = username
            session['role'] = user['role']
            session.permanent = True  # Make the session permanent
            return redirect(url_for('dashboard'))
        else:
            return "Login Failed! Incorrect username or password."

    return render_template('login.html')

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if 'user' not in session or session['role'] != 'staff':
        # Only staff can add users
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Server-side validation for username length
        if len(username) < 3:
            return "Username must be at least 3 characters long.", 400

        if len(password) < 6:
            return "Password must be at least 6 characters long.", 400

        
        db = get_db()
        # Check if the username already exists
        existing_user = query_db("SELECT * FROM users WHERE username = ?", [username], one=True)
        if existing_user:
            return "Error: Username already exists!", 400
        
        # Hash the password for security
        hashed_password = generate_password_hash(password)
        
        # Insert the new user into the database
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                   (username, hashed_password, role))
        db.commit()
        
        return redirect(url_for('dashboard'))  # Redirect to the dashboard after successful registration
    
    return render_template('register_user.html')



@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'user' not in session:
        return redirect(url_for('login'))  # Ensure the user is logged in
    
    if request.method == 'POST':
        username = request.form['username']
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Ensure new passwords match
        if new_password != confirm_password:
            return "Error: New passwords do not match!", 400
        
        db = get_db()
        # Retrieve the user from the database
        user = query_db("SELECT * FROM users WHERE username = ?", [username], one=True)
        if not user:
            return "Error: User not found!", 404

        # Check if the current password is correct
        if not check_password_hash(user[2], current_password):  # Assuming `user[2]` is the hashed password
            return "Error: Current password is incorrect!", 400
        
        # Hash the new password
        hashed_new_password = generate_password_hash(new_password)

        # Update the password in the database
        db.execute("UPDATE users SET password = ? WHERE username = ?", 
                   (hashed_new_password, username))
        db.commit()
        
        return redirect(url_for('dashboard'))  # Redirect to the dashboard after successful reset
    
    return render_template('reset_password.html')



# Dashboard (for both staff and members)
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
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                        "JOIN member_classes mc ON c.id = mc.class_id "
                        "WHERE mc.member_id = ?", [member_id])
    
    return render_template('member_classes.html', member=member, classes=classes)

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
    
    return render_template('register_class.html', member_id=member_id, classes=classes)

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

        # Input validation
        if not name or not re.match(r'^[A-Za-z\s]+$', name):
            return "Invalid name. Only letters and spaces are allowed."
        
        if status not in ['active', 'inactive']:
            return "Invalid membership status. Choose either 'active' or 'inactive'."
        
        # Continue with database insertion if validation passes
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
    
    # Delete member from the database
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    
    # Also delete any classes associated with the member in the member_classes table
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    
    db.commit()
    
    return redirect(url_for('view_members'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
