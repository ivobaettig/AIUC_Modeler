import sqlite3
import hashlib
from werkzeug.security import generate_password_hash

def migrate_database():
    conn = sqlite3.connect('data/activities.db')
    cursor = conn.cursor()
    
    # Check if we need to add the new columns
    columns_info = cursor.execute("PRAGMA table_info(activities)").fetchall()
    column_names = [col[1] for col in columns_info]
    
    # Add description column if it doesn't exist
    if 'description' not in column_names:
        print("Adding 'description' column...")
        cursor.execute("ALTER TABLE activities ADD COLUMN description TEXT")
    
    # Add uses_gpt column if it doesn't exist
    if 'uses_gpt' not in column_names:
        print("Adding 'uses_gpt' column...")
        cursor.execute("ALTER TABLE activities ADD COLUMN uses_gpt INTEGER DEFAULT 0")
    
    # Add solution column if it doesn't exist
    if 'solution' not in column_names:
        print("Adding 'solution' column...")
        cursor.execute("ALTER TABLE activities ADD COLUMN solution TEXT")
    
    # Create users table if it doesn't exist
    print("Creating users table if it doesn't exist...")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Add user_id column to activities if it doesn't exist
    if 'user_id' not in column_names:
        print("Adding 'user_id' column to activities table...")
        cursor.execute("ALTER TABLE activities ADD COLUMN user_id INTEGER DEFAULT NULL")
    
    # Check if default user exists, if not create it
    default_user = cursor.execute("SELECT id FROM users WHERE email = ?", ("ivo.baettig@unic.com",)).fetchone()
    
    if not default_user:
        print("Creating default user: ivo.baettig@unic.com...")
        # Generate a secure password hash - default password is 'password' (should be changed on first login)
        password_hash = generate_password_hash('password')
        cursor.execute(
            "INSERT INTO users (email, password, name) VALUES (?, ?, ?)",
            ("ivo.baettig@unic.com", password_hash, "Ivo Baettig")
        )
        default_user_id = cursor.lastrowid
        print(f"Created default user with ID: {default_user_id}")
    else:
        default_user_id = default_user[0]
        print(f"Default user already exists with ID: {default_user_id}")
    
    # Assign all existing activities to the default user
    print("Assigning existing activities to default user...")
    cursor.execute("UPDATE activities SET user_id = ? WHERE user_id IS NULL", (default_user_id,))
    print(f"Assigned {cursor.rowcount} activities to default user")
    
    # Update existing statuses to match new column names
    print("Updating status values...")
    status_mapping = {
        'Interesting': 'AI Case',
        'On hold': 'Check',
        'No use case': 'No AI Case'
    }
    
    # Get all activities
    activities = cursor.execute("SELECT id, status FROM activities").fetchall()
    
    # Update the status for each activity based on the mapping
    for activity_id, status in activities:
        if status in status_mapping:
            new_status = status_mapping[status]
            cursor.execute("UPDATE activities SET status = ? WHERE id = ?", (new_status, activity_id))
            print(f"Updated activity {activity_id} status from '{status}' to '{new_status}'")
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    print("Database migration completed successfully!")

if __name__ == "__main__":
    migrate_database()