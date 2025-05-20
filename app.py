from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_db_connection():
    conn = sqlite3.connect('data/activities.db')
    conn.row_factory = sqlite3.Row
    return conn

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Validate email format
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        name = request.form.get('name', '')
        
        # Form validation
        if not email or not password:
            flash('Email and password are required', 'error')
        elif not is_valid_email(email):
            flash('Please enter a valid email address', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            conn = get_db_connection()
            existing_user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
            
            if existing_user:
                conn.close()
                flash('Email already registered', 'error')
            else:
                hashed_password = generate_password_hash(password)
                conn.execute('INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
                          (email, hashed_password, name))
                conn.commit()
                
                # Get the new user_id
                user = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
                conn.close()
                
                # Log the user in
                session['user_id'] = user['id']
                session['user_email'] = email
                flash('Account created successfully!', 'success')
                return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    statuses = ['Backlog', 'AI Case', 'No AI Case', 'Implemented']
    activities_by_status = {
        status: conn.execute('SELECT * FROM activities WHERE status = ? AND user_id = ? ORDER BY timestamp DESC', 
                           (status, session['user_id'])).fetchall()
        for status in statuses
    }
    conn.close()
    return render_template('index.html', activities_by_status=activities_by_status, statuses=statuses)

@app.route('/add', methods=['POST'])
@login_required
def add():
    activity = request.form['activity']
    reflection = request.form['reflection']
    description = request.form.get('description', '')
    solution = request.form.get('solution', '')
    uses_gpt = 1 if request.form.get('uses_gpt') else 0
    status = 'Backlog'  # Default to Backlog instead of using form input
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO activities (activity, reflection, description, solution, uses_gpt, status, timestamp, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (activity, reflection, description, solution, uses_gpt, status, timestamp, session['user_id'])
    )
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    conn = get_db_connection()
    
    # First check if the activity belongs to the logged-in user
    activity = conn.execute('SELECT * FROM activities WHERE id = ? AND user_id = ?', 
                         (id, session['user_id'])).fetchone()
    
    if not activity:
        conn.close()
        flash('Activity not found or you do not have permission to edit it', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        activity = request.form['activity']
        reflection = request.form['reflection']
        description = request.form.get('description', '')
        solution = request.form.get('solution', '')
        uses_gpt = 1 if request.form.get('uses_gpt') else 0
        status = request.form['status']
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
        
        conn.execute(
            'UPDATE activities SET activity = ?, reflection = ?, description = ?, solution = ?, uses_gpt = ?, status = ?, timestamp = ? WHERE id = ? AND user_id = ?',
            (activity, reflection, description, solution, uses_gpt, status, timestamp, id, session['user_id'])
        )
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    
    statuses = ['Backlog', 'AI Case', 'No AI Case', 'Implemented']
    conn.close()
    return render_template('edit.html', activity=activity, statuses=statuses)

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM activities WHERE id = ? AND user_id = ?', (id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/update_status', methods=['POST'])
@login_required
def update_status():
    activity_id = request.json.get('activityId')
    new_status = request.json.get('newStatus')
    
    if not activity_id or not new_status:
        return jsonify({'success': False, 'error': 'Missing required data'}), 400
    
    try:
        conn = get_db_connection()
        
        # Check if the activity belongs to the logged-in user
        activity = conn.execute('SELECT id FROM activities WHERE id = ? AND user_id = ?', 
                             (activity_id, session['user_id'])).fetchone()
        
        if not activity:
            conn.close()
            return jsonify({'success': False, 'error': 'Activity not found or you do not have permission'}), 403
        
        conn.execute('UPDATE activities SET status = ? WHERE id = ?', (new_status, activity_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/update_card', methods=['POST'])
@login_required
def update_card():
    activity_id = request.json.get('activityId')
    activity = request.json.get('activity')
    reflection = request.json.get('reflection')
    description = request.json.get('description', '')
    solution = request.json.get('solution', '')
    uses_gpt = request.json.get('uses_gpt', 0)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    if not activity_id or not activity:
        return jsonify({'success': False, 'error': 'Missing required data'}), 400
    
    try:
        conn = get_db_connection()
        
        # Check if the activity belongs to the logged-in user
        activity_record = conn.execute('SELECT id FROM activities WHERE id = ? AND user_id = ?', 
                                  (activity_id, session['user_id'])).fetchone()
        
        if not activity_record:
            conn.close()
            return jsonify({'success': False, 'error': 'Activity not found or you do not have permission'}), 403
        
        conn.execute(
            'UPDATE activities SET activity = ?, reflection = ?, description = ?, solution = ?, uses_gpt = ?, timestamp = ? WHERE id = ?', 
            (activity, reflection, description, solution, uses_gpt, timestamp, activity_id)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'timestamp': timestamp})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if request.method == 'POST':
        name = request.form.get('name', '')
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Update name if provided
        if name:
            conn.execute('UPDATE users SET name = ? WHERE id = ?', (name, session['user_id']))
            conn.commit()
            flash('Profile updated successfully', 'success')
        
        # Update password if provided
        if current_password and new_password:
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
            elif not check_password_hash(user['password'], current_password):
                flash('Current password is incorrect', 'error')
            else:
                hashed_password = generate_password_hash(new_password)
                conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, session['user_id']))
                conn.commit()
                flash('Password updated successfully', 'success')
        
        # Refresh user data
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Get statistics
    activities_count = conn.execute('SELECT COUNT(*) FROM activities WHERE user_id = ?', 
                               (session['user_id'],)).fetchone()[0]
    
    ai_cases_count = conn.execute('SELECT COUNT(*) FROM activities WHERE user_id = ? AND status = ?', 
                             (session['user_id'], 'AI Case')).fetchone()[0]
    
    implemented_count = conn.execute('SELECT COUNT(*) FROM activities WHERE user_id = ? AND status = ?', 
                                (session['user_id'], 'Implemented')).fetchone()[0]
    
    conn.close()
    
    return render_template('profile.html', user=user, 
                         activities_count=activities_count, 
                         ai_cases_count=ai_cases_count, 
                         implemented_count=implemented_count)

if __name__ == '__main__':
    app.run(debug=True)
