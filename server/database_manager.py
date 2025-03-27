import sqlite3 # Added for SQLite database
from datetime import datetime # Added for timestamp
import json # Added for JSON response

class DatabaseManager:
    # Class-level variables for last reported attack details
    last_attack_type = None
    last_suspected_ip = None
    last_suspected_mac = None
    last_report_time = None

    def __init__(self, db_file):
        # Initialize the database
        self.db_file = db_file
        self.init_db()

    def init_db(self):
        """Initializes the SQLite database and user table."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        # Create the users table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')

        # Create the logs table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT NOT NULL,
                suspected_ip TEXT NOT NULL,
                suspected_mac TEXT NOT NULL,
                time TEXT NOT NULL
            )
        ''')

        # Commit and close the connection
        conn.commit()
        conn.close()

    def add_user(self, username, password):
        """Adds a user to the database (for signup)."""
        try:
            # Connect to the database and insert the user
            conn = sqlite3.connect(self.db_file)
            # Use a cursor to execute SQL queries
            cursor = conn.cursor()
            # Insert the user into the users table
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
        except sqlite3.Error as e:
            print(f"Error adding user: {e}")
        finally:
            conn.close()

    def user_exists(self, username):
        """Checks if a username already exists."""
        try:
            # Connect to the database and check if the user exists
            conn = sqlite3.connect(self.db_file)
            # Use a cursor to execute SQL queries
            cursor = conn.cursor()
            # Select the user with the given username
            cursor.execute('SELECT * FROM users WHERE username=?', (username,))
            # Fetch the user
            user = cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Error checking user: {e}")
            return False
        finally:
            conn.close()
        return user is not None

    def validate_login(self, username, password):
        """Validates the username and password during login."""
        try:
            # Connect to the database and check if the login is valid
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            # Select the user with the given username and password
            cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
            # Fetch the user
            user = cursor.fetchone()
        except sqlite3.Error as e:
            print(f"Error validating login: {e}")
            return False
        finally:
            conn.close()
        return user is not None

    def report_attack(self, attack_type, suspected_ip, suspected_mac):
        """Inserts a log entry for a detected attack."""
        current_time = datetime.now()

        # Check if the attack details match the last reported attack
        if (attack_type == self.last_attack_type and
                suspected_ip == self.last_suspected_ip and
                suspected_mac == self.last_suspected_mac and
                (current_time - self.last_report_time).total_seconds() < 20):
            #print("Duplicate attack detected. Skipping report.")
            return

        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            # Insert the attack details into the logs table
            cursor.execute('INSERT INTO logs (attack_type, suspected_ip, suspected_mac, time) VALUES (?, ?, ?, ?)', 
                        (attack_type, suspected_ip, suspected_mac, current_time.strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()

            # Update last reported attack details
            self.last_attack_type = attack_type
            self.last_suspected_ip = suspected_ip
            self.last_suspected_mac = suspected_mac
            self.last_report_time = current_time

        except sqlite3.Error as e:
            print(f"Error reporting attack: {e}")
        finally:
            conn.close()

    def get_logs_as_json(self):
        """Returns all logs in a JSON format."""
        try:
            # Connect to the database and retrieve all logs
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            # Select all logs from the logs table
            cursor.execute('SELECT * FROM logs')
            logs = cursor.fetchall()

            if not logs:
                return json.dumps({"logs": []})  # Return an empty list if no logs

            # Convert logs to a list of dictionaries
            logs_list = []
            for log in logs:
                log_id, attack_type, suspected_ip, suspected_mac, time = log
                logs_list.append({
                    "id": log_id,
                    "attack_type": attack_type,
                    "suspected_ip": suspected_ip or "N/A",  # Handle NULL values
                    "suspected_mac": suspected_mac or "N/A",  # Handle NULL values
                    "time": time
                })

            # Return the logs as JSON
            return json.dumps({"logs": logs_list}, indent=4)  # Pretty-printed JSON

        except sqlite3.Error as e:
            error_response = {"error": f"Error retrieving logs: {str(e)}"}
            return json.dumps(error_response, indent=4)
        finally:
            conn.close()