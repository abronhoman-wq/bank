import psycopg2
import bcrypt
import uuid
import random
import string
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, request, render_template, redirect, url_for, session, flash
import requests
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DB_CONFIG = {
"dbname": "central_bank_db",
"user": "postgres",
"password": "your_password",
"host": "localhost",
"port": "5432"
}

app = Flask(__name__)
app.secret_key = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode('utf-8')

salt = base64.urlsafe_b64encode(uuid.uuid4().bytes)
kdf = PBKDF2HMAC(
algorithm=hashes.SHA256(),
length=32,
salt=salt,
iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(b"your_encryption_key"))
cipher = Fernet(key)

SMS_API_URL = "https://sms-api.example.com/send"
SMS_API_KEY = "your_sms_api_key"

INITIAL_BALANCE = 5000000000000

def get_db_connection():
try:
conn = psycopg2.connect(**DB_CONFIG)
return conn
except psycopg2.Error as e:
logging.error(f"Database connection error: {e}")
return None

def encrypt_data(data):
return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
return cipher.decrypt(encrypted_data.encode()).decode()

def generate_otp(length=6):
return ''.join(random.choices(string.digits, k=length))

def hash_sensitive_data(data):
return hmac.new(salt, data.encode(), hashlib.sha256).hexdigest()

def send_sms(phone_number, message):
try:
payload = {
"api_key": SMS_API_KEY,
"phone_number": phone_number,
"message": message
}
response = requests.post(SMS_API_URL, json=payload, timeout=5)
if response.status_code == 200:
logging.info(f"SMS sent to {phone_number}")
return True
else:
logging.error(f"SMS sending failed: {response.text}")
return False
except requests.RequestException as e:
logging.error(f"SMS sending error: {e}")
return False

def create_database():
conn = get_db_connection()
if not conn:
return
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS accounts (
id SERIAL PRIMARY KEY,
owner_name VARCHAR(100) NOT NULL,
balance DECIMAL(20,2) NOT NULL CHECK (balance >= 0),
password_hash VARCHAR(256) NOT NULL,
phone_number VARCHAR(20),
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS credit_cards (
id SERIAL PRIMARY KEY,
account_id INTEGER REFERENCES accounts(id),
card_number VARCHAR(100) NOT NULL,
cvv2 VARCHAR(100) NOT NULL,
expiry_date VARCHAR(7) NOT NULL,
bank_name VARCHAR(50) NOT NULL,
credit_limit DECIMAL(20,2) NOT NULL CHECK (credit_limit >= 0),
available_credit DECIMAL(20,2) NOT NULL CHECK (available_credit >= 0),
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tax_account (
id SERIAL PRIMARY KEY,
balance DECIMAL(20,2) NOT NULL CHECK (balance >= 0),
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions (
id SERIAL PRIMARY KEY,
from_account_id INTEGER REFERENCES accounts(id),
to_account_id INTEGER REFERENCES accounts(id),
card_id INTEGER REFERENCES credit_cards(id),
amount DECIMAL(20,2) NOT NULL CHECK (amount > 0),
tax_amount DECIMAL(20,2) NOT NULL CHECK (tax_amount >= 0),
transaction_type VARCHAR(50) NOT NULL,
status VARCHAR(20) NOT NULL,
transaction_id VARCHAR(36) UNIQUE NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS otps (
id SERIAL PRIMARY KEY,
account_id INTEGER REFERENCES accounts(id),
otp_code VARCHAR(10) NOT NULL,
expires_at TIMESTAMP NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

cursor.execute("INSERT INTO tax_account (balance) VALUES (0) ON CONFLICT DO NOTHING")

conn.commit()
cursor.close()
conn.close()

def simulate_central_bank_api(account_id, card_number, amount, transaction_type):
logging.info(f"Simulated central bank API call: {transaction_type} for account {account_id}, card {card_number}, amount {amount}")
return True

def add_main_card():
owner_name = "Main Account"
password = "securepass123"
initial_balance = INITIAL_BALANCE
credit_limit = INITIAL_BALANCE
card_number = encrypt_data(str(uuid.uuid4().int)[:16])
cvv2 = encrypt_data(str(uuid.uuid4().int)[:3])
expiry_date = "2027/05"
bank_name = "Central Bank"
phone_number = "your_phone_number"

password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
conn = get_db_connection()
if not conn:
return None
cursor = conn.cursor()

try:
cursor.execute(
"INSERT INTO accounts (owner_name, balance, password_hash, phone_number) VALUES (%s, %s, %s, %s) RETURNING id",
(owner_name, initial_balance, password_hash, phone_number)
)
account_id = cursor.fetchone()[0]

cursor.execute(
"INSERT INTO credit_cards (account_id, card_number, cvv2, expiry_date, bank_name, credit_limit, available_credit) "
"VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
(account_id, card_number, cvv2, expiry_date, bank_name, credit_limit, initial_balance)
)
card_id = cursor.fetchone()[0]

transaction_id = str(uuid.uuid4())
cursor.execute(
"INSERT INTO transactions (from_account_id, card_id, amount, tax_amount, transaction_type, status, transaction_id) "
"VALUES (%s, %s, %s, %s, %s, %s, %s)",
(account_id, card_id, initial_balance, 0, 'charge', 'success', transaction_id)
)

simulate_central_bank_api(account_id, decrypt_data(card_number), initial_balance, 'charge')
send_sms(phone_number, f"Account charged with {initial_balance} IRR. Transaction ID: {transaction_id}")

conn.commit()
return account_id, card_id, decrypt_data(card_number)
except psycopg2.Error as e:
logging.error(f"Error: {e}")
conn.rollback()
return None
finally:
cursor.close()
conn.close()

def add_new_card(owner_name, password, phone_number="your_phone_number"):
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
card_number = encrypt_data(str(uuid.uuid4().int)[:16])
cvv2 = encrypt_data(str(uuid.uuid4().int)[:3])
expiry_date = "2028/01"
bank_name = "Central Bank"
initial_balance = INITIAL_BALANCE
credit_limit = INITIAL_BALANCE

conn = get_db_connection()
if not conn:
return None
cursor = conn.cursor()

try:
cursor.execute(
"INSERT INTO accounts (owner_name, balance, password_hash, phone_number) VALUES (%s, %s, %s, %s) RETURNING id",
(owner_name, initial_balance, password_hash, phone_number)
)
account_id = cursor.fetchone()[0]

cursor.execute(
"INSERT INTO credit_cards (account_id, card_number, cvv2, expiry_date, bank_name, credit_limit, available_credit) "
"VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
(account_id, card_number, cvv2, expiry_date, bank_name, credit_limit, initial_balance)
)
card_id = cursor.fetchone()[0]

transaction_id = str(uuid.uuid4())
cursor.execute(
"INSERT INTO transactions (from_account_id, card_id, amount, tax_amount, transaction_type, status, transaction_id) "
"VALUES (%s, %s, %s, %s, %s, %s, %s)",
(account_id, card_id, initial_balance, 0, 'charge', 'success', transaction_id)
)

simulate_central_bank_api(account_id, decrypt_data(card_number), initial_balance, 'charge')
send_sms(phone_number, f"Account charged with {initial_balance} IRR. Transaction ID: {transaction_id}")

conn.commit()
return account_id, card_id, decrypt_data(card_number)
except psycopg2.Error as e:
logging.error(f"Error: {e}")
conn.rollback()
return None
finally:
cursor.close()
conn.close()

def authenticate(owner_name, password):
conn = get_db_connection()
if not conn:
return None
cursor = conn.cursor()

cursor.execute("SELECT id, password_hash, phone_number FROM accounts WHERE owner_name = %s", (owner_name,))
result = cursor.fetchone()

if result and bcrypt.checkpw(password.encode('utf-8'), result[1].encode('utf-8')):
otp_code = generate_otp()
expires_at = datetime.now() + timedelta(minutes=5)
cursor.execute(
"INSERT INTO otps (account_id, otp_code, expires_at) VALUES (%s, %s, %s)",
(result[0], otp_code, expires_at)
)
conn.commit()
send_sms(result[2], f"Your OTP is {otp_code} (valid for 5 minutes)")
cursor.close()
conn.close()
return result[0]

cursor.close()
conn.close()
return None

def verify_otp(account_id, otp_code):
conn = get_db_connection()
if not conn:
return False
cursor = conn.cursor()

cursor.execute(
"SELECT otp_code, expires_at FROM otps WHERE account_id = %s ORDER BY created_at DESC LIMIT 1",
(account_id,)
)
result = cursor.fetchone()

cursor.close()
conn.close()

if result and result[0] == otp_code and result[1] > datetime.now():
return True
return False

def get_credit_balance(card_id):
conn = get_db_connection()
if not conn:
return None
cursor = conn.cursor()

cursor.execute("SELECT available_credit FROM credit_cards WHERE id = %s", (card_id,))
result = cursor.fetchone()

cursor.close()
conn.close()
return result[0] if result else None

def get_all_balances():
conn = get_db_connection()
if not conn:
return []
cursor = conn.cursor()

cursor.execute("SELECT owner_name, available_credit FROM credit_cards JOIN accounts ON credit_cards.account_id = accounts.id")
balances = cursor.fetchall()

cursor.close()
conn.close()
return balances

def transfer_funds(account_id, card_id, to_card_number, amount, tax_rate=0.01):
if amount < 1000 or amount > 100_000_000_000_000:
    return False, "Amount must be between 1000 and 100 trillion IRR."

    tax_amount = amount * tax_rate
    total_amount = amount + tax_amount

    conn = get_db_connection()
    if not conn:
    return False, "Database connection error"
    cursor = conn.cursor()

    try:
    conn.autocommit = False

    cursor.execute(
    "SELECT available_credit, account_id FROM credit_cards WHERE id = %s AND account_id = %s FOR UPDATE",
    (card_id, account_id)
    )
    card_balance = cursor.fetchone()
    if not card_balance or card_balance[0]  < total_amount:
        return False, "Insufficient balance (including tax)."

        cursor.execute("SELECT id, account_id, available_credit FROM credit_cards WHERE card_number = %s", (encrypt_data(to_card_number),))
        to_card = cursor.fetchone()
        if not to_card:
        return False, "Destination card not found."
        to_card_id, to_account_id, to_balance = to_card

        cursor.execute(
        "UPDATE credit_cards SET available_credit = available_credit - %s WHERE id = %s",
        (total_amount, card_id)
        )
        cursor.execute(
        "UPDATE credit_cards SET available_credit = available_credit + %s WHERE id = %s",
        (amount, to_card_id)
        )
        cursor.execute("UPDATE tax_account SET balance = balance + %s WHERE id = 1", (tax_amount,))

        transaction_id = str(uuid.uuid4())
        cursor.execute(
        "INSERT INTO transactions (from_account_id, to_account_id, card_id, amount, tax_amount, transaction_type, status, transaction_id) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (account_id, to_account_id, card_id, amount, tax_amount, 'transfer', 'success', transaction_id)
        )

        cursor.execute("SELECT phone_number FROM accounts WHERE id = %s", (account_id,))
        phone_number = cursor.fetchone()[0]
        send_sms(phone_number, f"Transfer of {amount} IRR to card ending {to_card_number[-4:]} successful. Tax: {tax_amount} IRR. Transaction ID: {transaction_id}")

        cursor.execute("SELECT phone_number FROM accounts WHERE id = %s", (to_account_id,))
        to_phone_number = cursor.fetchone()[0]
        send_sms(to_phone_number, f"Received {amount} IRR from card ending {decrypt_data(card_balance[1])[-4:]} Transaction ID: {transaction_id}")

        simulate_central_bank_api(account_id, decrypt_data(card_balance[1]), amount, 'transfer')

        conn.commit()
        return True, transaction_id
        except psycopg2.Error as e:
        conn.rollback()
        logging.error(f"Transfer error: {e}")
        return False, str(e)
        finally:
        cursor.close()
        conn.close()

        def withdraw_pos_or_atm(account_id, card_id, amount, device_type, tax_rate=0.01):
        if amount < 1000 or amount > 100_000_000_000_000:
            return False, "Amount must be between 1000 and 100 trillion IRR."

            tax_amount = amount * tax_rate
            total_amount = amount + tax_amount

            conn = get_db_connection()
            if not conn:
            return False, "Database connection error"
            cursor = conn.cursor()

            try:
            conn.autocommit = False

            cursor.execute(
            "SELECT available_credit FROM credit_cards WHERE id = %s AND account_id = %s FOR UPDATE",
            (card_id, account_id)
            )
            card_balance = cursor.fetchone()
            if not card_balance or card_balance[0] < total_amount:
                return False, "Insufficient balance (including tax)."

                cursor.execute(
                "SELECT account_id, available_credit FROM credit_cards WHERE owner_name = 'POS Device' LIMIT 1"
                )
                pos_account = cursor.fetchone()
                if not pos_account:
                pos_account_id, _, _ = add_new_card("POS Device", "pos1234")
                else:
                pos_account_id = pos_account[0]

                cursor.execute(
                "UPDATE credit_cards SET available_credit = available_credit - %s WHERE id = %s",
                (total_amount, card_id)
                )
                cursor.execute(
                "UPDATE credit_cards SET available_credit = available_credit + %s WHERE account_id = %s",
                (amount, pos_account_id)
                )
                cursor.execute("UPDATE tax_account SET balance = balance + %s WHERE id = 1", (tax_amount,))

                transaction_id = str(uuid.uuid4())
                transaction_type = f"withdraw_{device_type}"
                cursor.execute(
                "INSERT INTO transactions (from_account_id, to_account_id, card_id, amount, tax_amount, transaction_type, status, transaction_id) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (account_id, pos_account_id, card_id, amount, tax_amount, transaction_type, 'success', transaction_id)
                )

                cursor.execute("SELECT phone_number FROM accounts WHERE id = %s", (account_id,))
                phone_number = cursor.fetchone()[0]
                send_sms(phone_number, f"Withdrawal of {amount} IRR via {device_type.upper()} successful. Tax: {tax_amount} IRR. Transaction ID: {transaction_id}")

                simulate_central_bank_api(account_id, card_id, amount, transaction_type)

                conn.commit()
                return True, transaction_id
                except psycopg2.Error as e:
                conn.rollback()
                logging.error(f"Withdrawal error: {e}")
                return False, str(e)
                finally:
                cursor.close()
                conn.close()

                def purchase(account_id, card_id, amount, tax_rate=0.02):
                if amount < 1000 or amount > 100_000_000_000_000:
                    return False, "Amount must be between 1000 and 100 trillion IRR."

                    tax_amount = amount * tax_rate
                    total_amount = amount + tax_amount

                    conn = get_db_connection()
                    if not conn:
                    return False, "Database connection error"
                    cursor = conn.cursor()

                    try:
                    conn.autocommit = False

                    cursor.execute(
                    "SELECT available_credit FROM credit_cards WHERE id = %s AND account_id = %s FOR UPDATE",
                    (card_id, account_id)
                    )
                    card_balance = cursor.fetchone()
                    if not card_balance or card_balance[0] < total_amount:
                        return False, "Insufficient balance (including tax)."

                        cursor.execute(
                        "SELECT account_id, available_credit FROM credit_cards WHERE owner_name = 'Store' LIMIT 1"
                        )
                        store_account = cursor.fetchone()
                        if not store_account:
                        store_account_id, _, _ = add_new_card("Store", "store1234")
                        else:
                        store_account_id = store_account[0]

                        cursor.execute(
                        "UPDATE credit_cards SET available_credit = available_credit - %s WHERE id = %s",
                        (total_amount, card_id)
                        )
                        cursor.execute(
                        "UPDATE credit_cards SET available_credit = available_credit + %s WHERE account_id = %s",
                        (amount, store_account_id)
                        )
                        cursor.execute("UPDATE tax_account SET balance = balance + %s WHERE id = 1", (tax_amount,))

                        transaction_id = str(uuid.uuid4())
                        cursor.execute(
                        "INSERT INTO transactions (from_account_id, to_account_id, card_id, amount, tax_amount, transaction_type, status, transaction_id) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (account_id, store_account_id, card_id, amount, tax_amount, 'purchase', 'success', transaction_id)
                        )

                        cursor.execute("SELECT phone_number FROM accounts WHERE id = %s", (account_id,))
                        phone_number = cursor.fetchone()[0]
                        send_sms(phone_number, f"Purchase of {amount} IRR successful. Tax: {tax_amount} IRR. Transaction ID: {transaction_id}")

                        simulate_central_bank_api(account_id, card_id, amount, 'purchase')

                        conn.commit()
                        return True, transaction_id
                        except psycopg2.Error as e:
                        conn.rollback()
                        logging.error(f"Purchase error: {e}")
                        return False, str(e)
                        finally:
                        cursor.close()
                        conn.close()

                        def get_tax_report():
                        conn = get_db_connection()
                        if not conn:
                        return None, []
                        cursor = conn.cursor()

                        cursor.execute("SELECT balance FROM tax_account WHERE id = 1")
                        total_tax = cursor.fetchone()[0]

                        cursor.execute(
                        "SELECT amount, tax_amount, transaction_type, created_at "
                        "FROM transactions WHERE tax_amount > 0 ORDER BY created_at DESC"
                        )
                        tax_transactions = cursor.fetchall()

                        cursor.close()
                        conn.close()
                        return total_tax, tax_transactions

                        def get_transaction_history(account_id):
                        conn = get_db_connection()
                        if not conn:
                        return []
                        cursor = conn.cursor()

                        cursor.execute(
                        """
                        SELECT t.transaction_id, t.from_account_id, t.to_account_id, t.card_id, t.amount, t.tax_amount, t.transaction_type, t.status, t.created_at,
                        a1.owner_name as from_name, a2.owner_name as to_name, c.card_number, c.bank_name
                        FROM transactions t
                        LEFT JOIN accounts a1 ON t.from_account_id = a1.id
                        LEFT JOIN accounts a2 ON t.to_account_id = a2.id
                        LEFT JOIN credit_cards c ON t.card_id = c.id
                        WHERE t.from_account_id = %s OR t.to_account_id = %s
                        ORDER BY t.created_at DESC
                        """,
                        (account_id, account_id)
                        )
                        transactions = cursor.fetchall()

                        transactions_decrypted = []
                        for t in transactions:
                        transaction_id, from_account_id, to_account_id, card_id, amount, tax_amount, transaction_type, status, created_at, from_name, to_name, card_number, bank_name = t
                        card_number = decrypt_data(card_number) if card_number else None
                        transactions_decrypted.append((transaction_id, from_account_id, to_account_id, card_id, amount, tax_amount, transaction_type, status, created_at, from_name, to_name, card_number, bank_name))

                        cursor.close()
                        conn.close()
                        return transactions_decrypted

                        @app.route('/')
                        def index():
                        if 'account_id' not in session:
                        return redirect(url_for('login'))
                        return redirect(url_for('dashboard'))

                        @app.route('/login', methods=['GET', 'POST'])
                        def login():
                        if request.method == 'POST':
                        owner_name = request.form['owner_name']
                        password = request.form['password']
                        account_id = authenticate(owner_name, password)
                        if account_id:
                        session['account_id_pending'] = account_id
                        return redirect(url_for('otp_verify'))
                        flash("Invalid username or password.")
                        return render_template('login.html')

                        @app.route('/otp_verify', methods=['GET', 'POST'])
                        def otp_verify():
                        if 'account_id_pending' not in session:
                        return redirect(url_for('login'))

                        if request.method == 'POST':
                        otp_code = request.form['otp_code']
                        account_id = session['account_id_pending']
                        if verify_otp(account_id, otp_code):
                        session['account_id'] = account_id
                        session.pop('account_id_pending', None)
                        return redirect(url_for('dashboard'))
                        flash("Invalid or expired OTP.")
                        return render_template('otp.html')

                        @app.route('/dashboard')
                        def dashboard():
                        if 'account_id' not in session:
                        return redirect(url_for('login'))

                        account_id = session['account_id']
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM credit_cards WHERE account_id = %s", (account_id,))
                        card_id = cursor.fetchone()[0]
                        cursor.execute("SELECT owner_name FROM accounts WHERE id = %s", (account_id,))
                        owner_name = cursor.fetchone()[0]
                        cursor.close()
                        conn.close()

                        balance = get_credit_balance(card_id)
                        all_balances = get_all_balances()
                        return render_template('dashboard.html', balance=balance, owner_name=owner_name, all_balances=all_balances)

                        @app.route('/transfer', methods=['GET', 'POST'])
                        def transfer():
                        if 'account_id' not in session:
                        return redirect(url_for('login'))

                        account_id = session['account_id']
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM credit_cards WHERE account_id = %s", (account_id,))
                        card_id = cursor.fetchone()[0]
                        cursor.close()
                        conn.close()

                        if request.method == 'POST':
                        to_card_number = request.form['to_card_number']
                        amount = float(request.form['amount'])
                        success, message = transfer_funds(account_id, card_id, to_card_number, amount)
                        if success:
                        flash(f"Transfer successful. Transaction ID: {message}")
                        else:
                        flash(f"Error: {message}")
                        return redirect(url_for('dashboard'))
                        return render_template('transfer.html')

                        @app.route('/purchase', methods=['GET', 'POST'])
                        def purchase():
                        if 'account_id' not in session:
                        return redirect(url_for('login'))

                        account_id = session['account_id']
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM credit_cards WHERE account_id = %s", (account_id,))
                        card_id = cursor.fetchone()[0]
                        cursor.close()
                        conn.close()

                        if request.method == 'POST':
                        amount = float(request.form['amount'])
                        success, message = purchase(account_id, card_id, amount)
                        if success:
                        flash(f"Purchase successful. Transaction ID: {message}")
                        else:
                        flash(f"Error: {message}")
                        return redirect(url_for('dashboard'))
                        return render_template('purchase.html')

                        @app.route('/pos_withdraw', methods=['GET', 'POST'])
                        def pos_withdraw():
                        if 'account_id' not in session:
                        return redirect(url_for('login'))

                        account_id = session['account_id']
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM credit_cards WHERE account_id = %s", (account_id,))
                        card_id = cursor.fetchone()[0]
                        cursor.close()
                        conn.close()

                        if request.method == 'POST':
                        amount = float(request.form['amount'])
                        success, message = withdraw_pos_or_atm(account_id, card_id, amount, 'pos')
                        if success:
                        flash(f"Withdrawal from POS successful. Transaction ID: {message}")
                        else:
                        flash(f"Error: {message}")
                        return redirect(url_for('dashboard'))
                        return render_template('pos_withdraw.html')

                        @app.route('/atm_withdraw', methods=['GET', 'POST'])
                        def atm_withdraw():
                        if 'account_id' not in session:
                        return redirect(url_for('login'))

                        account_id = session['account_id']
                        conn = get_db_connection()
                        cursor = conn.cursor()
                        cursor.execute("SELECT id FROM credit_cards WHERE account_id = %s", (account_id,))
                        card_id = cursor.fetchone()[0]
                        cursor.close()
                        conn.close()

                        if request.method == 'POST':
                        amount = float(request.form['amount'])
                        success, message = withdraw_pos_or_atm(account_id, card_id, amount, 'atm')
                        if success:
                        flash(f"Withdrawal from ATM successful. Transaction ID: {message}")
                        else:
                        flash(f"Error: {message}")
                        return redirect(url_for('dashboard'))
                        return render_template('atm_withdraw.html')

                        @app.route('/history')
                        def history():
                        if 'account_id' not in session:
                        return redirect(url_for('login'))

                        account_id = session['account_id']
                        transactions = get_transaction_history(account_id)
                        return render_template('history.html', transactions=transactions)

                        @app.route('/tax_report')
                        def tax_report():
                        if 'account_id' not in session:
                        return redirect(url_for('login'))

                        total_tax, tax_transactions = get_tax_report()
                        if total_tax is None:
                        flash("Error retrieving tax report.")
                        return redirect(url_for('dashboard'))
                        return render_template('tax_report.html', total_tax=total_tax, tax_transactions=tax_transactions)

                        @app.route('/logout')
                        def logout():
                        session.pop('account_id', None)
                        return redirect(url_for('login'))

                        base_html = """
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>{% block title %}{% endblock %}</title>
                            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                            <style>
                                body {
                                    background-color: #f8f9fa;
                                    font-family: Arial, sans-serif;
                                }
                                .container {
                                    max-width: 800px;
                                    margin-top: 50px;
                                }
                                .card {
                                    border-radius: 15px;
                                    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                                }
                                .btn-primary {
                                    background-color: #007bff;
                                    border: none;
                                }
                                .btn-primary:hover {
                                    background-color: #0056b3;
                                }
                                .btn-secondary {
                                    background-color: #6c757d;
                                }
                                .btn-secondary:hover {
                                    background-color: #5a6268;
                                }
                                .btn-danger {
                                    background-color: #dc3545;
                                }
                                .btn-danger:hover {
                                    background-color: #c82333;
                                }
                                .alert {
                                    margin-top: 20px;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                {% with messages = get_flashed_messages(with_categories=true) %}
                                {% if messages %}
                                {% for category, message in messages %}
                                <div class="alert alert-{{ 'success' if category == 'message' else 'danger' }}" role="alert">
                                    {{ message }}
                                </div>
                                {% endfor %}
                                {% endif %}
                                {% endwith %}
                                {% block content %}{% endblock %}
                            </div>
                            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
                        </body>
                    </html>
                    """

                    login_html = """
                    {% extends "base.html" %}
                    {% block title %}Login{% endblock %}
                    {% block content %}
                    <div class="card p-4">
                        <h1 class="text-center mb-4">Login to System</h1>
                        <form method="post">
                            <div class="mb-3">
                                <label for="owner_name" class="form-label">Username</label>
                                <input type="text" class="form-control" id="owner_name" name="owner_name" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Password</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Login</button>
                        </form>
                    </div>
                    {% endblock %}
                    """

                    otp_html = """
                    {% extends "base.html" %}
                    {% block title %}OTP Verification{% endblock %}
                    {% block content %}
                    <div class="card p-4">
                        <h1 class="text-center mb-4">Verify OTP Code</h1>
                        <form method="post">
                            <div class="mb-3">
                                <label for="otp_code" class="form-label">OTP Code</label>
                                <input type="text" class="form-control" id="otp_code" name="otp_code" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Verify</button>
                        </form>
                    </div>
                    {% endblock %}
                    """

                    dashboard_html = """
                    {% extends "base.html" %}
                    {% block title %}Dashboard{% endblock %}
                    {% block content %}
                    <div class="card p-4">
                        <h1 class="text-center mb-4">Welcome</h1>
                        <div class="text-center mb-3">
                            <p>
                                Account Holder: <strong>{{ owner_name }}</strong>
                            </p>
                            <p>
                                Balance: <strong>{{ balance }} IRR</strong>
                            </p>
                        </div>
                        <h2 class="text-center mb-3">All Account Balances</h2>
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Account Holder</th>
                                    <th>Balance (IRR)</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for balance in all_balances %}
                                <tr>
                                    <td>{{ balance[0] }}</td>
                                    <td>{{ balance[1] }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        <div class="d-flex flex-wrap justify-content-center gap-2">
                            <a href="{{ url_for('transfer') }}" class="btn btn-primary">Transfer Funds</a>
                            <a href="{{ url_for('purchase') }}" class="btn btn-primary">Purchase</a>
                            <a href="{{ url_for('pos_withdraw') }}" class="btn btn-primary">Withdraw from POS</a>
                            <a href="{{ url_for('atm_withdraw') }}" class="btn btn-primary">Withdraw from ATM</a>
                            <a href="{{ url_for('history') }}" class="btn btn-primary">Transaction History</a>
                            <a href="{{ url_for('tax_report') }}" class="btn btn-primary">Tax Report</a>
                            <a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
                        </div>
                    </div>
                    {% endblock %}
                    """

                    transfer_html = """
                    {% extends "base.html" %}
                    {% block title %}Transfer Funds{% endblock %}
                    {% block content %}
                    <div class="card p-4">
                        <h1 class="text-center mb-4">Transfer Funds</h1>
                        <form method="post">
                            <div class="mb-3">
                                <label for="to_card_number" class="form-label">Destination Card Number</label>
                                <input type="text" class="form-control" id="to_card_number" name="to_card_number" required>
                            </div>
                            <div class="mb-3">
                                <label for="amount" class="form-label">Amount (IRR)</label>
                                <input type="number" class="form-control" id="amount" name="amount" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Transfer</button>
                        </form>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary w-100 mt-3">Back</a>
                    </div>
                    {% endblock %}
                    """

                    purchase_html = """
                    {% extends "base.html" %}
                    {% block title %}Purchase{% endblock %}
                    {% block content %}
                    <div class="card p-4">
                        <h1 class="text-center mb-4">Purchase</h1>
                        <form method="post">
                            <div class="mb-3">
                                <label for="amount" class="form-label">Amount (IRR)</label>
                                <input type="number" class="form-control" id="amount" name="amount" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Pay</button>
                        </form>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary w-100 mt-3">Back</a>
                    </div>
                    {% endblock %}
                    """

                    pos_withdraw_html = """
                    {% extends "base.html" %}
                    {% block title %}Withdraw from POS{% endblock %}
                    {% block content %}
                    <div class="card p-4">
                        <h1 class="text-center mb-4">Withdraw from POS Device</h1>
                        <form method="post">
                            <div class="mb-3">
                                <label for="amount" class="form-label">Amount (IRR)</label>
                                <input type="number" class="form-control" id="amount" name="amount" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Withdraw</button>
                        </form>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary w-100 mt-3">Back</a>
                    </div>
                    {% endblock %}
                    """

                    atm_withdraw_html = """
                    {% extends "base.html" %}
                    {% block title %}Withdraw from ATM{% endblock %}
                    {% block content %}
                    <div class="card p-4">
                        <h1 class="text-center mb-4">Withdraw from ATM Device</h1>
                        <form method="post">
                            <div class="mb-3">
                                <label for="amount" class="form-label">Amount (IRR)</label>
                                <input type="number" class="form-control" id="amount" name="amount" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Withdraw</button>
                        </form>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary w-100 mt-3">Back</a>
                    </div>
                    {% endblock %}
                    """

                    history_html = """
                    {% extends "base.html" %}
                    {% block title %}Transaction History{% endblock %}
                    {% block content %}
                    <div class="card p-4">
                        <h1 class="text-center mb-4">Transaction History</h1>
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Transaction ID</th>
                                    <th>From</th>
                                    <th>To</th>
                                    <th>Amount</th>
                                    <th>Tax</th>
                                    <th>Type</th>
                                    <th>Status</th>
                                    <th>Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for t in transactions %}
                                <tr>
                                    <td>{{ t[0] }}</td>
                                    <td>{{ t[9] }}</td>
                                    <td>{{ t[10] or '---' }}</td>
                                    <td>{{ t[4] }}</td>
                                    <td>{{ t[5] }}</td>
                                    <td>{{ t[6] }}</td>
                                    <td>{{ t[7] }}</td>
                                    <td>{{ t[8] }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary w-100 mt-3">Back</a>
                    </div>
                    {% endblock %}
                    """

                    tax_report_html = """
                    {% extends "base.html" %}
                    {% block title %}Tax Report{% endblock %}
                    {% block content %}
                    <div class="card p-4">
                        <h1 class="text-center mb-4">Tax Report</h1>
                        <p class="text-center">
                            Total Tax: {{ total_tax }} IRR
                        </p>
                        <h2 class="mt-4">Tax Transaction Details</h2>
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Amount</th>
                                    <th>Tax</th>
                                    <th>Type</th>
                                    <th>Time</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for t in tax_transactions %}
                                <tr>
                                    <td>{{ t[0] }}</td>
                                    <td>{{ t[1] }}</td>
                                    <td>{{ t[2] }}</td>
                                    <td>{{ t[3] }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary w-100 mt-3">Back</a>
                    </div>
                    {% endblock %}
                    """

                    with open('templates/base.html', 'w', encoding='utf-8') as f:
                    f.write(base_html)
                    with open('templates/login.html', 'w', encoding='utf-8') as f:
                    f.write(login_html)
                    with open('templates/otp.html', 'w', encoding='utf-8') as f:
                    f.write(otp_html)
                    with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
                    f.write(dashboard_html)
                    with open('templates/transfer.html', 'w', encoding='utf-8') as f:
                    f.write(transfer_html)
                    with open('templates/purchase.html', 'w', encoding='utf-8') as f:
                    f.write(purchase_html)
                    with open('templates/pos_withdraw.html', 'w', encoding='utf-8') as f:
                    f.write(pos_withdraw_html)
                    with open('templates/atm_withdraw.html', 'w', encoding='utf-8') as f:
                    f.write(atm_withdraw_html)
                    with open('templates/history.html', 'w', encoding='utf-8') as f:
                    f.write(history_html)
                    with open('templates/tax_report.html', 'w', encoding='utf-8') as f:
                    f.write(tax_report_html)

                    create_database()
                    add_main_card()

                    if __name__ == "__main__":
                    app.run(debug=True)

