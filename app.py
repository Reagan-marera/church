from flask import Flask, jsonify, request
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from models import db, User, OTP, ChartOfAccounts, InvoiceIssued, CashReceiptJournal, CashDisbursementJournal,Church,TithePledge,Payment
from functools import wraps
from werkzeug.security import generate_password_hash
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import random
import string
import  logging
from datetime import date
import requests
import json
from sqlalchemy.orm import joinedload
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///financial_reporting.db'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'reaganstrongkey'
mail = Mail(app)  
mail.init_app(app)
db.init_app(app)
migrate = Migrate(app, db)
CORS(app)
jwt = JWTManager(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True 
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'transactionsfinance355@gmail.com'  
app.config['MAIL_PASSWORD'] = 'rvzxngpossphfgzm'  
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Access token expires in 1 hour
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(hours=3)  # Refresh token expires in 3 hours


mail = Mail(app)
logging.basicConfig(level=logging.DEBUG) 

def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorated(*args, **kwargs):
            current_user = User.query.filter_by(username=get_jwt_identity()).first()
            if not current_user or current_user.role != role:
                return jsonify({'message': 'Access forbidden: Insufficient privileges'}), 403
            return fn(*args, **kwargs)
        return decorated
    return wrapper


def parse_date(date_str):
    """Parse a date string in 'YYYY-MM-DD' format to a date object."""
    try:
        return date.fromisoformat(date_str)
    except ValueError:
        return None



@app.route('/request_reset_password', methods=['POST'])
def request_reset_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        logging.warning("Email not provided in request")
        return jsonify({"error": "Email is required"}), 400

    logging.debug(f"Received password reset request for email: {email}")

    user = User.query.filter(User.email.ilike(email)).first()
    if not user:
        logging.warning(f"No user found with email: {email}")
        return jsonify({"error": "User with this email does not exist"}), 404

    otp = generate_otp()
    store_otp(email, otp)

    username = user.username
    logging.debug(f"Generated OTP: {otp} for user: {username}")

    msg = Message('Password Reset Request', sender='noreply@yourapp.com', recipients=[email])
    msg.body = f"""
    Hello, {username}

    Here's the verification code to reset your password:

    {otp}

    To reset your password, enter this verification code when prompted.

    This code will expire in 5 minutes.

    If you did not request this password reset, please ignore this email.
    """

    try:
        mail.send(msg)
        logging.info(f"OTP email sent to {email}")
        return jsonify({"message": "OTP sent to your email"}), 200
    except Exception as e:
        logging.error(f"Failed to send OTP email to {email}: {e}", exc_info=True)
        return jsonify({"error": f"Failed to send OTP email: {e}"}), 500


# Helper Functions
def generate_otp():
    """Generate a random 6-digit OTP."""
    return ''.join(random.choices(string.digits, k=6))


def store_otp(email, otp):
    """Store the OTP in the database or any other storage for verification."""
    # This function should implement the logic to save the OTP
    logging.debug(f"Storing OTP: {otp} for email: {email}")

@app.route('/get_user_role_by_email', methods=['POST'])
def get_user_role_by_email():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    return jsonify({'role': user.role}), 200
 
@app.route('/check_email_exists', methods=['POST'])
def check_email_exists():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'message': 'Email exists'}), 200
    else:
        return jsonify({'error': 'Email not found'}), 404

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    otp_entry = OTP.query.filter_by(email=email).first()

    if not otp_entry:
        return jsonify({"error": "OTP not requested or does not exist"}), 404

    if datetime.utcnow() > otp_entry.expiry:
        return jsonify({
            "error": "OTP expired",
            "message": "Did time run out? Request a new OTP.",
            "request_new_otp": True
        }), 400

    if otp_entry.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    return jsonify({"message": "OTP is valid"}), 200  # Fixed return statement

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    if not email or not otp or not new_password:
        return jsonify({"error": "Missing email, OTP or new password"}), 400

    otp_entry = OTP.query.filter_by(email=email).first()
    if not otp_entry:
        return jsonify({"error": "OTP not requested"}), 404

    if datetime.utcnow() > otp_entry.expiry:
        return jsonify({"error": "OTP expired"}), 400

    if otp_entry.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    db.session.delete(otp_entry)
    db.session.commit()

    return jsonify({"message": "Password reset successfully"}), 200

@app.route('/request_new_otp', methods=['POST'])
def request_new_otp():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    otp = generate_otp()
    store_otp(email, otp)

    username = user.username  
    msg = Message('Password Reset Request', sender='noreply@yourapp.com', recipients=[email])
    msg.body = f"""
    Hello, {username}

    Here's the verification code to reset your password:

    {otp}

    To reset your password, enter this verification code when prompted.

    This code will expire in 5 minutes.

    If you did not request this password reset, please ignore this email.
    """
    mail.send(msg)

    return jsonify({"message": "New OTP sent to your email"}), 200

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def store_otp(email, otp):
    expiry = datetime.utcnow() + timedelta(minutes=5)
    otp_entry = OTP.query.filter_by(email=email).first()
    if otp_entry:
        otp_entry.otp = otp
        otp_entry.expiry = expiry
    else:
        otp_entry = OTP(email=email, otp=otp, expiry=expiry)
        db.session.add(otp_entry)
    db.session.commit()
 
 
 
 
@app.route('/register', methods=['POST'])
def register_user():
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Check if the required fields are present
        required_fields = ['username', 'email', 'password', 'role']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400

        # Check if the username or email already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'message': 'Username already exists'}), 400
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already exists'}), 400

        # Handle Church creation if the user is Church CEO
        if data['role'] == 'Church CEO':
            # Ensure Church information is provided
            church_data = data.get('church')
            if not church_data or not all(field in church_data for field in ['name', 'address', 'phone_number', 'email']):
                return jsonify({'error': 'Missing church information'}), 400

            # Check if the church already exists (based on the email, which should be unique for each church)
            existing_church = Church.query.filter_by(email=church_data['email']).first()
            if existing_church:
                return jsonify({'message': 'A church with this email already exists'}), 400

            # Create new Church if it doesn't exist
            church = Church(
                name=church_data['name'],
                address=church_data['address'],
                phone_number=church_data['phone_number'],
                email=church_data['email']
            )
            db.session.add(church)
            db.session.commit()

            # Create the Church CEO user and link them to the church
            user = User(
                username=data['username'],
                email=data['email'],
                role=data['role'],
                church_id=church.id  # Link the Church CEO to the newly created church
            )
        
        else:
            # Create user for role 'Member' or other roles
            if data['role'] == 'Member':
                if not all(field in data for field in ['residence', 'phone_number', 'occupation', 'member_number', 'church_name']):
                    return jsonify({'error': 'Missing member-specific fields or church_name'}), 400

                # Look up the church by name
                church_name = data['church_name']
                church = Church.query.filter_by(name=church_name).first()

                if not church:
                    return jsonify({'error': 'Church not found with the provided name'}), 400

                # Check if the member_number already exists in the same church
                existing_member = User.query.filter_by(member_number=data['member_number'], church_id=church.id).first()
                if existing_member:
                    return jsonify({'error': 'Member number already exists in this church'}), 400

                # Create the Member user and link to the found church
                user = User(
                    username=data['username'],
                    email=data['email'],
                    role=data['role'],
                    residence=data['residence'],
                    phone_number=data['phone_number'],
                    occupation=data['occupation'],
                    member_number=data['member_number'],
                    church_id=church.id  # Link the member to the existing church
                )

            else:
                # Create user for any other roles
                user = User(
                    username=data['username'],
                    email=data['email'],
                    role=data['role']
                )

        # Hash the password and save the user
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()

        logging.info(f"User {data['username']} registered successfully.")
        return jsonify({'message': 'User registered successfully'}), 201

    except Exception as e:
        logging.error(f"Error registering user: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Check if username and password are provided
    if not all(field in data for field in ['username', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        # Create JWT token with both username and role in the identity
        token = create_access_token(identity={"id": user.id, "username": user.username, "role": user.role})
        return jsonify({'token': token, 'role': user.role}), 200

    return jsonify({'message': 'Invalid username or password'}), 401

# CEO-specific routes
@app.route('/users', methods=['GET'])
@role_required('Church CEO')
def get_all_users():
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role
    } for user in users])

@app.route('/users/<int:id>', methods=['DELETE'])
@role_required('Church CEO')
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

# Route to get all transactions
@app.route('/transactions', methods=['GET'])
@role_required('Church CEO')
def get_all_transactions():
    # Query all required models
    invoices = InvoiceIssued.query.all()
    cash_receipts = CashReceiptJournal.query.all()
    cash_disbursements = CashDisbursementJournal.query.all()

    # Prepare the transactions dictionary
    transactions = {
        'invoices_issued': [{
            'id': invoice.id,
            'invoice_number': invoice.invoice_number,
            'date_issued': invoice.date_issued,
            'amount': invoice.amount,
            'account_class': invoice.account_class,
            'account_type': invoice.account_type,
            'account_debited': invoice.account_debited,
            'account_credited': invoice.account_credited,
            'grn_number': invoice.grn_number,
            'parent_account': invoice.parent_account  # Added parent_account
        } for invoice in invoices],
        
        'cash_receipts': [{
            'id': receipt.id,
            'receipt_date': receipt.receipt_date,
            'receipt_no': receipt.receipt_no,
            'from_whom_received': receipt.from_whom_received,
            'description': receipt.description,
            'account_class': receipt.account_class,
            'account_type': receipt.account_type,
            'receipt_type': receipt.receipt_type,
            'account_debited': receipt.account_debited,
            'account_credited': receipt.account_credited,
            'cash': receipt.cash,
            'total': receipt.total,
            'parent_account': receipt.parent_account  # Added parent_account
        } for receipt in cash_receipts],
        
        'cash_disbursements': [{
            'id': disbursement.id,
            'disbursement_date': disbursement.disbursement_date,
            'cheque_no': disbursement.cheque_no,
            'to_whom_paid': disbursement.to_whom_paid,
            'payment_type': disbursement.payment_type,
            'description': disbursement.description,
            'account_class': disbursement.account_class,
            'account_type': disbursement.account_type,
            'account_debited': disbursement.account_debited,
            'account_credited': disbursement.account_credited,
            'cash': disbursement.cash,
            'bank': disbursement.bank,
            'parent_account': disbursement.parent_account  # Added parent_account
        } for disbursement in cash_disbursements]
    }

    return jsonify(transactions)

# Route to manage the chart of accounts (GET and POST)
@app.route('/chart-of-accounts', methods=['GET', 'POST'])
@jwt_required()
def manage_chart_of_accounts():
    # Get the current user_id from the JWT (Make sure you're extracting just the id)
    current_user_data = get_jwt_identity()  # This should return the JWT payload (likely a dictionary)
    current_user_id = current_user_data.get('id')  # Extract the 'id' specifically

    if request.method == 'GET':
        # Filter accounts by the current user's ID
        accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()

        return jsonify([{
            'id': acc.id,
            'parent_account': acc.parent_account,
            'account_name': acc.account_name,
            'account_type': acc.account_type,
            'sub_account_details': acc.sub_account_details or []  # Handle None case
        } for acc in accounts])

    elif request.method == 'POST':
        data = request.get_json()

        # Ensure required fields are provided
        if not all(key in data for key in ['parent_account', 'account_name', 'account_type']):
            return jsonify({'error': 'Missing required fields'}), 400

        # Ensure sub_account_details is either None, a dictionary, or a list
        sub_account_details = data.get('sub_account_details', None)
        if sub_account_details and not isinstance(sub_account_details, (dict, list)):
            return jsonify({'error': 'sub_account_details should be a JSON object or list'}), 400

        # Create a new account for the current user
        new_account = ChartOfAccounts(
            parent_account=data['parent_account'],
            account_name=data['account_name'],
            account_type=data['account_type'],
            sub_account_details=sub_account_details or [],  # Default to empty list if None
            user_id=current_user_id
        )

        try:
            db.session.add(new_account)
            db.session.commit()
            return jsonify({'message': 'Chart of Accounts created successfully'}), 201
        except :
            db.session.rollback()  # Rollback on failure
            return jsonify({'error': 'Failed to create account, possible data integrity issue'}), 400
# Route to update or delete chart of accounts (PUT and DELETE)
@app.route('/chart-of-accounts/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_chart_of_accounts(id):
    account = ChartOfAccounts.query.get_or_404(id)
    current_user_data = get_jwt_identity()  # Get the JWT identity
    current_user_id = current_user_data.get('id')  # Extract 'id' from JWT payload
    current_username = current_user_data.get('username')  # Extract 'username' from JWT payload

    # Ensure that the user is authorized to modify or delete this account by matching the username
    if account.user_id != current_user_id:
        return jsonify({'error': 'You do not have permission to modify or delete this account'}), 403

    # Optionally, check if the username matches if you want extra protection
    if account.user.username != current_username:
        return jsonify({'error': 'You do not have permission to delete this account'}), 403

    if request.method == 'PUT':
        data = request.get_json()

        # Ensure sub_account_details is either None, a dictionary, or a list
        sub_account_details = data.get('sub_account_details', None)
        if sub_account_details and not isinstance(sub_account_details, (dict, list)):
            return jsonify({'error': 'sub_account_details should be a JSON object or list'}), 400

        # Update account fields with provided data
        account.parent_account = data.get('parent_account', account.parent_account)
        account.account_name = data.get('account_name', account.account_name)
        account.account_type = data.get('account_type', account.account_type)
        account.sub_account_details = sub_account_details if sub_account_details is not None else account.sub_account_details

        db.session.commit()
        return jsonify({'message': 'Chart of Accounts updated successfully'})

    elif request.method == 'DELETE':
        db.session.delete(account)
        db.session.commit()
        return jsonify({'message': 'Chart of Accounts deleted successfully'})
@app.route('/invoices', methods=['GET', 'POST'])
@jwt_required()
def manage_invoices():
    try:
        # Get current user identity from JWT (assuming 'id' is available in the JWT payload)
        current_user = get_jwt_identity()

        if isinstance(current_user, dict):
            user_id = current_user.get('id')  # Get the 'id' from the JWT payload

        if request.method == 'GET':
            # Fetch invoices associated with the current user's 'user_id'
            invoices = InvoiceIssued.query.options(joinedload(InvoiceIssued.user)) \
                .filter_by(user_id=user_id).all()

            return jsonify([{
                'id': inv.id,
                'invoice_number': inv.invoice_number,
                'date_issued': inv.date_issued.isoformat() if inv.date_issued else None,
                'account_type': inv.account_type,
                'amount': inv.amount,
                'username': inv.user.username,  # Access username from related User model
                'account_class': inv.account_class,
                'account_debited': inv.account_debited,
                'account_credited': inv.account_credited,
                'description': inv.description,
                'grn_number': inv.grn_number,
                'parent_account': inv.parent_account,
                'sub_accounts': inv.sub_accounts
            } for inv in invoices]), 200

        elif request.method == 'POST':
            data = request.get_json()

            # Handle date_issued conversion and sub_accounts as a dictionary
            date_issued_str = data.get('date_issued')
            date_issued = datetime.fromisoformat(date_issued_str) if date_issued_str else None
            sub_accounts = data.get('sub_accounts', {})

            # Create and save the new invoice with the user_id
            new_invoice = InvoiceIssued(
                invoice_number=data['invoice_number'],
                date_issued=date_issued,
                account_type=data['account_type'],
                amount=float(data['amount']),
                account_class=data['account_class'],
                account_debited=data.get('account_debited'),
                account_credited=data.get('account_credited'),
                description=data.get('description'),
                grn_number=data.get('grn_number'),
                user_id=user_id,  # Use the user_id from the current_user
                parent_account=data['parent_account'],
                sub_accounts=sub_accounts
            )

            db.session.add(new_invoice)
            db.session.commit()

            return jsonify({'message': 'Invoice created successfully'}), 201

    except Exception as e:
        app.logger.error(f"Error managing invoices: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500

@app.route('/invoices/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_invoice(id):
    try:
        # Extract current user's identity from JWT (e.g., user_id or username)
        current_user = get_jwt_identity()  # This should return a dictionary containing user information
        invoice = InvoiceIssued.query.get_or_404(id)

        # Ensure the invoice belongs to the current user (user_id)
        if invoice.user_id != current_user['id']:  # Assuming current_user contains user_id
            return jsonify({'error': 'Unauthorized access to invoice'}), 403

        if request.method == 'PUT':
            data = request.get_json()

            # Ensure 'sub_accounts' is provided and is a valid JSON object
            if 'sub_accounts' in data:
                sub_accounts = data['sub_accounts']
                if not isinstance(sub_accounts, dict):
                    return jsonify({'error': 'sub_accounts must be a valid JSON object.'}), 400
                invoice.sub_accounts = sub_accounts

            # Update fields if provided
            if 'invoice_number' in data:
                # Ensure invoice number is unique
                existing_invoice = InvoiceIssued.query.filter_by(invoice_number=data['invoice_number']).first()
                if existing_invoice and existing_invoice.id != id:  # Ensure it's not the same invoice
                    return jsonify({'error': 'Invoice number already exists'}), 400
                invoice.invoice_number = data['invoice_number']

            if 'date_issued' in data:
                try:
                    invoice.date_issued = datetime.strptime(data['date_issued'], '%Y-%m-%d').date()  # Convert to date
                except ValueError:
                    return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

            # Update other fields (optional fields)
            invoice.account_type = data.get('account_type', invoice.account_type)
            invoice.amount = float(data.get('amount', invoice.amount))
            invoice.account_class = data.get('account_class', invoice.account_class)
            invoice.account_debited = data.get('account_debited', invoice.account_debited)
            invoice.account_credited = data.get('account_credited', invoice.account_credited)
            invoice.grn_number = data.get('grn_number', invoice.grn_number)  # Update GRN number if provided
            invoice.parent_account = data.get('parent_account', invoice.parent_account)  # Update parent_account if provided

            db.session.commit()
            return jsonify({'message': 'Invoice updated successfully'}), 200

        elif request.method == 'DELETE':
            db.session.delete(invoice)
            db.session.commit()
            return jsonify({'message': 'Invoice deleted successfully'}), 200

    except Exception as e:
        app.logger.error(f"Error processing invoice {id}: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500

@app.route('/cash-receipt-journals', methods=['GET', 'POST'])
@jwt_required()
def manage_cash_receipt_journals():
    try:
        current_user = get_jwt_identity()  # Get the current user's identity
        current_user_id = current_user.get('id')  # Extract the user ID
        app.logger.info(f"JWT Identity (current_user): {current_user}")

        if request.method == 'POST':
            data = request.get_json()
            app.logger.info(f"Received data: {data}")

            # Validate required fields
            required_fields = [
                'receipt_date', 'receipt_no', 'from_whom_received',
                'account_class', 'account_type', 'receipt_type',
                'cash', 'bank', 'parent_account', 'cashbook'
            ]
            missing_fields = [field for field in required_fields if not data.get(field)]
            if missing_fields:
                return jsonify({'error': f'Missing fields: {", ".join(missing_fields)}'}), 400

            # Validate receipt_date format
            try:
                receipt_date = datetime.strptime(data['receipt_date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

            # Check for duplicate receipt_no for the current user
            if CashReceiptJournal.query.filter_by(created_by=current_user_id, receipt_no=data['receipt_no']).first():
                return jsonify({'error': f'Receipt number {data["receipt_no"]} already exists for your account.'}), 400

            # Validate numeric fields
            try:
                cash = float(data['cash'])
                bank = float(data['bank'])
            except ValueError:
                return jsonify({'error': 'Cash and Bank must be numeric values.'}), 400

            # Validate and process sub_accounts
            sub_accounts = data.get('sub_accounts', {})  # Default to empty dictionary
            if not isinstance(sub_accounts, dict):
                return jsonify({'error': 'Sub-accounts must be a valid JSON object.'}), 400

            # Ensure either account_debited or account_credited is provided (one can be null)
            account_debited = data.get('account_debited')
            account_credited = data.get('account_credited')
            if not account_debited and not account_credited:
                return jsonify({'error': 'Either account_debited or account_credited must be provided.'}), 400

            # Calculate the total field
            total = cash + bank

            # Create a new CashReceiptJournal entry
            new_journal = CashReceiptJournal(
                receipt_date=receipt_date,
                receipt_no=data['receipt_no'],
                ref_no=data.get('ref_no'),
                from_whom_received=data['from_whom_received'],
                description=data.get('description'),
                account_class=data['account_class'],
                account_type=data['account_type'],
                receipt_type=data['receipt_type'],
                account_debited=account_debited,  # Can be nullable
                account_credited=account_credited,  # Can be nullable
                cash=cash,
                bank=bank,
                total=total,
                parent_account=data['parent_account'],
                cashbook=data['cashbook'],  # Include cashbook field
                sub_accounts=sub_accounts,  # Handle sub_accounts field
                created_by=current_user_id  # Use current_user_id here
            )
            db.session.add(new_journal)
            db.session.commit()

            return jsonify({'message': 'Journal entry created successfully'}), 201

        elif request.method == 'GET':
            # Fetch all journals created by the current user
            journals = CashReceiptJournal.query.filter_by(created_by=current_user_id).all()
            result = [
                {
                    'id': journal.id,
                    'receipt_date': journal.receipt_date.strftime('%Y-%m-%d'),
                    'receipt_no': journal.receipt_no,
                    'ref_no': journal.ref_no,
                    'from_whom_received': journal.from_whom_received,
                    'description': journal.description,
                    'account_class': journal.account_class,
                    'account_type': journal.account_type,
                    'receipt_type': journal.receipt_type,
                    'account_debited': journal.account_debited,
                    'account_credited': journal.account_credited,
                    'cash': journal.cash,
                    'bank': journal.bank,
                    'parent_account': journal.parent_account,
                    'cashbook': journal.cashbook,  # Include cashbook in the response
                    'total': journal.total,
                    'sub_accounts': journal.sub_accounts,  # Include sub_accounts in the response
                }
                for journal in journals
            ]

            return jsonify(result), 200

    except Exception as e:
        app.logger.error(f"Error: {e}")
        return jsonify({'error': 'An error occurred while processing the request'}), 500

@app.route('/cash-receipt-journals/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_cash_receipt_journal(id):
    try:
        journal = CashReceiptJournal.query.get(id)

        if not journal:
            return jsonify({"error": "Journal not found"}), 404

        current_user = get_jwt_identity()

        # Debugging log: Print current user and journal created_by to check if they match
        app.logger.debug(f"JWT identity: {current_user}")
        app.logger.debug(f"Journal created by: {journal.created_by}")

        # Fix: Compare current_user['id'] with journal.created_by
        if journal.created_by != current_user['id']:
            return jsonify({"error": "Unauthorized access"}), 403

        if request.method == 'PUT':
            data = request.get_json()

            # Validate and update fields
            if 'receipt_no' in data and data['receipt_no'] != journal.receipt_no:
                if CashReceiptJournal.query.filter_by(receipt_no=data['receipt_no']).first():
                    return jsonify({'error': f'Receipt number {data["receipt_no"]} already exists.'}), 400

            if 'receipt_date' in data:
                try:
                    journal.receipt_date = datetime.strptime(data['receipt_date'], '%Y-%m-%d').date()
                except ValueError:
                    return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

            # Update all provided fields
            journal.receipt_no = data.get('receipt_no', journal.receipt_no)
            journal.ref_no = data.get('ref_no', journal.ref_no)
            journal.from_whom_received = data.get('from_whom_received', journal.from_whom_received)
            journal.description = data.get('description', journal.description)
            journal.account_class = data.get('account_class', journal.account_class)
            journal.account_type = data.get('account_type', journal.account_type)
            journal.account_debited = data.get('account_debited', journal.account_debited)
            journal.account_credited = data.get('account_credited', journal.account_credited)
            journal.cash = data.get('cash', journal.cash)
            journal.bank = data.get('bank', journal.bank)
            journal.parent_account = data.get('parent_account', journal.parent_account)  # Update parent_account if provided

            journal.save()

            return jsonify({'message': 'Journal entry updated successfully'}), 200

        elif request.method == 'DELETE':
            db.session.delete(journal)
            db.session.commit()
            return jsonify({"message": "Journal entry deleted successfully"}), 200

    except Exception as e:
        app.logger.error(f"Error updating/deleting cash receipt journal: {e}")
        return jsonify({"error": "An error occurred while processing your request"}), 500

@app.route('/cash-disbursement-journals', methods=['GET', 'POST'])
@jwt_required()
def manage_cash_disbursement_journals():
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('id') if isinstance(current_user, dict) else current_user

        if request.method == 'GET':
            # Fetch all journals for the current user
            journals = CashDisbursementJournal.query.filter_by(created_by=user_id).all()
            return jsonify([
                {
                    'id': journal.id,
                    'disbursement_date': journal.disbursement_date.isoformat(),
                    'cheque_no': journal.cheque_no,
                    'p_voucher_no': journal.p_voucher_no,
                    'to_whom_paid': journal.to_whom_paid,
                    'description': journal.description,
                    'account_class': journal.account_class,
                    'account_type': journal.account_type,
                    'account_credited': journal.account_credited,
                    'account_debited': journal.account_debited,
                    'parent_account': journal.parent_account,
                    'cashbook': journal.cashbook,
                    'payment_type': journal.payment_type,
                    'cash': journal.cash,
                    'bank': journal.bank,
                    'total': journal.total,
                    'sub_accounts': journal.sub_accounts,  # Added sub_accounts
                    'created_by_user': journal.created_by_user.username if journal.created_by_user else 'Unknown'
                }
                for journal in journals
            ])

        elif request.method == 'POST':
            data = request.get_json()

            # Parse and validate the date
            disbursement_date = parse_date(data.get('disbursement_date'))
            if not disbursement_date:
                return jsonify({"error": "Invalid date format. Use 'YYYY-MM-DD'."}), 400

            # Check for duplicate cheque_no for the current user
            cheque_no = data.get('cheque_no')
            existing_journal = CashDisbursementJournal.query.filter_by(created_by=user_id, cheque_no=cheque_no).first()
            if existing_journal:
                return jsonify({"error": f"Cheque number {cheque_no} already exists for this user."}), 400

            # Remove account validation for 'account_credited' and 'account_debited'
            account_credited = data.get('account_credited')
            account_debited = data.get('account_debited')
            parent_account = data.get('parent_account')

            # Skip checking the ChartOfAccounts table
            # If you still want to validate other fields (like sub_accounts or cash), you can leave those checks in place.

            # Validate sub_accounts (Optional JSON field)
            sub_accounts = data.get('sub_accounts')
            if sub_accounts and not isinstance(sub_accounts, dict):
                return jsonify({"error": "Invalid sub_accounts format. Must be a JSON object."}), 400

            # Create the journal entry
            new_journal = CashDisbursementJournal(
                disbursement_date=disbursement_date,
                cheque_no=cheque_no,
                p_voucher_no=data.get('p_voucher_no'),
                to_whom_paid=data['to_whom_paid'],
                description=data.get('description'),
                account_class=data['account_class'],
                account_type=data['account_type'],
                payment_type=data['payment_type'],
                cashbook=data['cashbook'],
                account_credited=account_credited,
                account_debited=account_debited,
                parent_account=parent_account,
                sub_accounts=sub_accounts,  # Include sub_accounts here
                cash=float(data.get('cash', 0)),
                bank=float(data.get('bank', 0)),
                created_by=user_id
            )

            # Calculate total
            new_journal.total = new_journal.cash + new_journal.bank

            # Save to database
            db.session.add(new_journal)
            db.session.commit()
            return jsonify({"message": "Cash Disbursement Journal entry created successfully"}), 201

    except Exception as e:
        app.logger.error(f"Error managing cash disbursement journals: {e}")
        return jsonify({"error": "An error occurred while processing the request."}), 500

@app.route('/cash-disbursement-journals/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_cash_disbursement_journals(id):
    current_user = get_jwt_identity()
    user_id = current_user.get('id') if isinstance(current_user, dict) else current_user

    # Fetch journal entry and verify ownership
    journal = CashDisbursementJournal.query.filter_by(id=id, created_by=user_id).first()
    if not journal:
        return jsonify({"error": "Journal entry not found or unauthorized"}), 404

    if request.method == 'PUT':
        data = request.get_json()

        # Validate accounts
        account_credited = data.get('account_credited', journal.account_credited)
        account_debited = data.get('account_debited', journal.account_debited)

        coa_entry_credited = ChartOfAccounts.query.filter_by(user_id=user_id, account_name=account_credited).first()
        coa_entry_debited = ChartOfAccounts.query.filter_by(user_id=user_id, account_name=account_debited).first()

        if not coa_entry_credited or not coa_entry_debited:
            return jsonify({"error": "Invalid account credited or debited."}), 400

        # Validate sub_accounts (Optional)
        sub_accounts = data.get('sub_accounts', journal.sub_accounts)
        if sub_accounts and not isinstance(sub_accounts, dict):
            return jsonify({"error": "Invalid sub_accounts format. Must be a JSON object."}), 400

        # Update fields
        journal.disbursement_date = parse_date(data.get('disbursement_date')) or journal.disbursement_date
        journal.cheque_no = data.get('cheque_no', journal.cheque_no)
        journal.p_voucher_no = data.get('p_voucher_no', journal.p_voucher_no)
        journal.to_whom_paid = data.get('to_whom_paid', journal.to_whom_paid)
        journal.description = data.get('description', journal.description)
        journal.account_class = data.get('account_class', journal.account_class)
        journal.account_type = data.get('account_type', journal.account_type)
        journal.payment_type = data.get('payment_type', journal.payment_type)
        journal.cashbook = data.get('cashbook', journal.cashbook)
        journal.account_credited = account_credited
        journal.account_debited = account_debited
        journal.parent_account = data.get('parent_account', journal.parent_account)
        journal.sub_accounts = sub_accounts
        journal.cash = float(data.get('cash', journal.cash))
        journal.bank = float(data.get('bank', journal.bank))
        journal.total = journal.cash + journal.bank

        db.session.commit()
        return jsonify({"message": "Cash Disbursement Journal entry updated successfully"})

    elif request.method == 'DELETE':
        db.session.delete(journal)
        db.session.commit()
        return jsonify({"message": "Cash Disbursement Journal entry deleted successfully"})
@app.route('/usertransactions', methods=['GET'])
@jwt_required()
def get_user_transactions():
    # Get the current user's data from the JWT
    current_user_data = get_jwt_identity()
    current_user_id = current_user_data.get('id')
    current_user_role = current_user_data.get('role')

    # Determine whether the user is a CEO
    if current_user_role == 'CEO':
        # If the user is a CEO, return all transactions
        invoices = InvoiceIssued.query.all()
        cash_receipts = CashReceiptJournal.query.all()
        cash_disbursements = CashDisbursementJournal.query.all()
    else:
        # Otherwise, return transactions for the current user
        invoices = InvoiceIssued.query.filter_by(user_id=current_user_id).all()
        cash_receipts = CashReceiptJournal.query.filter_by(created_by=current_user_id).all()
        cash_disbursements = CashDisbursementJournal.query.filter_by(created_by=current_user_id).all()

    # Prepare the transactions dictionary
    transactions = {
        'invoices_issued': [{
            'id': invoice.id,
            'invoice_number': invoice.invoice_number,
            'date_issued': invoice.date_issued.strftime('%Y-%m-%d'),
            'amount': invoice.amount,
            'account_class': invoice.account_class,
            'account_type': invoice.account_type,
            'account_debited': invoice.account_debited,
            'account_credited': invoice.account_credited,
            'grn_number': invoice.grn_number,
            'parent_account': invoice.parent_account,
            'sub_accounts': invoice.sub_accounts  # Assuming it's stored as JSON
        } for invoice in invoices],
        
        'cash_receipts': [{
            'id': receipt.id,
            'receipt_date': receipt.receipt_date.strftime('%Y-%m-%d'),
            'receipt_no': receipt.receipt_no,
            'from_whom_received': receipt.from_whom_received,
            'description': receipt.description,
            'account_class': receipt.account_class,
            'account_type': receipt.account_type,
            'receipt_type': receipt.receipt_type,
            'account_debited': receipt.account_debited,
            'account_credited': receipt.account_credited,
            'cash': receipt.cash,
            'total': receipt.total,
            'parent_account': receipt.parent_account,
            'sub_accounts': receipt.sub_accounts  # Assuming it's stored as JSON
        } for receipt in cash_receipts],
        
        'cash_disbursements': [{
            'id': disbursement.id,
            'disbursement_date': disbursement.disbursement_date.strftime('%Y-%m-%d'),
            'cheque_no': disbursement.cheque_no,
            'to_whom_paid': disbursement.to_whom_paid,
            'payment_type': disbursement.payment_type,
            'description': disbursement.description,
            'account_class': disbursement.account_class,
            'account_type': disbursement.account_type,
            'account_debited': disbursement.account_debited,
            'account_credited': disbursement.account_credited,
            'cash': disbursement.cash,
            'bank': disbursement.bank,
            'total': disbursement.total,
            'parent_account': disbursement.parent_account,
            'sub_accounts': disbursement.sub_accounts  # Assuming it's stored as JSON
        } for disbursement in cash_disbursements]
    }

    return jsonify(transactions)

@app.route('/member/<username>', methods=['GET'])
@jwt_required()  # Ensure the user is authenticated
def get_member_info(username):
    current_user_identity = get_jwt_identity()  # Get the user identity from the JWT token
    current_user_id = current_user_identity.get('username')  # Extract the username (as a string)
    current_user_role = current_user_identity.get('role')  # Extract the role from the token

    # Fetch the current user from the database
    current_user = User.query.filter_by(username=current_user_id).first()

    if not current_user:
        return jsonify({"error": "User not found"}), 404

    # If the current user is the Church CEO, they can view all members of their church
    if current_user_role == 'Church CEO':
        # Fetch all members from the same church (by church_id)
        members = User.query.filter_by(church_id=current_user.church_id).all()
        all_members_info = [
            {
                "username": member.username,
                "email": member.email,
                "role": member.role,
                "residence": member.residence,
                "phone_number": member.phone_number,
                "occupation": member.occupation,
                "member_number": member.member_number,
                "church_name": member.church.name if member.church else "Unknown Church"  # Get church name
            }
            for member in members
        ]
        return jsonify({"all_members_info": all_members_info}), 200

    # If the current user is not the CEO, they can only view their own information
    if current_user.username != username:  # Ensure you're comparing username
        return jsonify({"error": "Unauthorized access"}), 403

    # Fetch the member information for the requested username
    member = User.query.filter_by(username=username).first()
    if not member:
        return jsonify({"error": "Member not found"}), 404

    return jsonify({
        "member_info": {
            "username": member.username,
            "email": member.email,
            "role": member.role,
            "residence": member.residence,
            "phone_number": member.phone_number,
            "occupation": member.occupation,
            "member_number": member.member_number,
            "church_name": member.church.name if member.church else "Unknown Church"  # Get church name
        }
    }), 200

@app.route('/create-pledge', methods=['GET', 'POST'])
@jwt_required()  # Ensure the user is authenticated using JWT
def create_or_get_tithe_pledge():
    current_user_identity = get_jwt_identity()
    current_user_id = current_user_identity.get('username')  # Get the username of the current user

    if not current_user_id:
        return jsonify({"error": "Authenticated user does not have a username"}), 400

    # If the method is POST (create a new pledge)
    if request.method == 'POST':
        data = request.get_json()  # Get JSON data from the request

        # Ensure required fields are in the request data
        amount_pledged = data.get('amount_pledged')
        month = data.get('month')
        year = data.get('year')

        if not amount_pledged or not month or not year:
            return jsonify({"error": "Missing required fields: amount_pledged, month, and year"}), 400

        # Ensure amount_pledged is a valid number (float or int)
        try:
            amount_pledged = float(amount_pledged)
        except ValueError:
            return jsonify({"error": "Invalid amount_pledged format. It should be a valid number."}), 400

        # Find the user by the username from the JWT
        user = User.query.filter_by(username=current_user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Find the church associated with the user (assuming the church_id is in the User model)
        church = Church.query.get(user.church_id)
        if not church:
            return jsonify({"error": "Church not found for user"}), 404

        try:
            # Calculate the total amount (monthly pledge * 12)
            total_amount = amount_pledged * 12

            # Ensure that total_amount is reasonable (optional: limit range to avoid overflow issues)
            if total_amount > 1e12:  # Adjust this threshold as necessary
                return jsonify({"error": "Calculated total amount is too large."}), 400

            # Set the remaining amount to be the same as the total amount initially
            remaining_amount = total_amount

            # Create the new TithePledge
            tithe_pledge = TithePledge(
                amount_pledged=amount_pledged,
                month=month,
                year=year,
                member_id=user.id,  # Using the user ID
                church_id=church.id,  # Using the church ID
                total_amount=total_amount,
                remaining_amount=remaining_amount,
                timestamp=datetime.utcnow()  # Automatically set the timestamp to current UTC time
            )

            # Add the new TithePledge to the database
            db.session.add(tithe_pledge)
            db.session.commit()

            return jsonify({"message": "Tithe pledge created successfully"}), 201

        except Exception as e:
            db.session.rollback()  # Rollback in case of an error
            return jsonify({"error": "Failed to create pledge", "details": str(e)}), 500

    # If the method is GET (retrieve pledges)
    elif request.method == 'GET':
        user = User.query.filter_by(username=current_user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        pledges = TithePledge.query.filter_by(member_id=user.id).all()

        pledge_list = [{
            'id': pledge.id,
            'amount_pledged': pledge.amount_pledged,
            'month': pledge.month,
            'year': pledge.year,
            'total_amount': pledge.total_amount,
            'remaining_amount': pledge.remaining_amount,  # Show the remaining amount to be paid
            'username': current_user_id,
            'timestamp': pledge.timestamp.isoformat() if pledge.timestamp else None  # Check if timestamp is None
        } for pledge in pledges]

        return jsonify({"pledges": pledge_list}), 200


    
    
@app.route('/update-pledge/<int:pledge_id>', methods=['PUT'])
@jwt_required()
def update_tithe_pledge(pledge_id):
    data = request.get_json()
    current_user_identity = get_jwt_identity()
    current_user_id = current_user_identity.get('username')

    if not current_user_id:
        return jsonify({"error": "Authenticated user does not have a username"}), 400
    
    pledge = TithePledge.query.get(pledge_id)
    if not pledge:
        return jsonify({"error": "Pledge not found"}), 404

    if pledge.member_id != current_user_identity['id']:
        return jsonify({"error": "Unauthorized to update this pledge"}), 403

    amount_pledged = data.get('amount_pledged')
    month = data.get('month')
    year = data.get('year')
    
    if amount_pledged:
        pledge.amount_pledged = amount_pledged
    if month:
        pledge.month = month
    if year:
        pledge.year = year

    try:
        db.session.commit()
        return jsonify({"message": "Tithe pledge updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to update pledge", "details": str(e)}), 500
    
    
@app.route('/delete-pledge/<int:pledge_id>', methods=['DELETE'])
@jwt_required()
def delete_tithe_pledge(pledge_id):
    # Retrieve the identity of the current user from the JWT token
    current_user_identity = get_jwt_identity()
    current_user_id = current_user_identity.get('id')  # Get the user ID from the JWT token identity

    # Ensure the current user has an ID in the JWT token
    if not current_user_id:
        return jsonify({"error": "Authenticated user does not have an ID"}), 400

    # Retrieve the pledge from the database
    pledge = TithePledge.query.get(pledge_id)

    # If the pledge does not exist, return a 404 error
    if not pledge:
        return jsonify({"error": "Pledge not found"}), 404

    # Check if the current user is authorized to delete the pledge (check if the user owns the pledge)
    if pledge.member_id != current_user_id:
        return jsonify({"error": "Unauthorized to delete this pledge"}), 403

    # Try to delete the pledge from the database
    try:
        db.session.delete(pledge)
        db.session.commit()
        return jsonify({"message": "Tithe pledge deleted successfully"}), 200
    except Exception as e:
        # In case of an error, roll back the transaction and return a 500 error
        db.session.rollback()
        return jsonify({"error": "Failed to delete pledge", "details": str(e)}), 500
    
    
@app.route('/make-payment', methods=['POST'])
@jwt_required()  # Ensure the user is authenticated
def make_payment():
    current_user_identity = get_jwt_identity()
    current_user_id = current_user_identity.get('username')  # Get the username of the current user

    if not current_user_id:
        return jsonify({"error": "Authenticated user does not have a username"}), 400

    # Get JSON data from request
    data = request.get_json()

    # Ensure the required fields are present
    pledge_id = data.get('pledge_id')
    amount_paid = data.get('amount_paid')

    if not pledge_id or not amount_paid:
        return jsonify({"error": "Missing required fields: pledge_id and amount_paid"}), 400

    try:
        # Ensure amount_paid is a float
        amount_paid = float(amount_paid)
    except ValueError:
        return jsonify({"error": "Invalid amount_paid value, must be a number"}), 400

    # Find the user by the username from the JWT
    user = User.query.filter_by(username=current_user_id).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Find the pledge by ID
    pledge = TithePledge.query.get(pledge_id)
    if not pledge:
        return jsonify({"error": "Pledge not found"}), 404

    # Ensure that the pledge belongs to the current user
    if pledge.member_id != user.id:
        return jsonify({"error": "You are not authorized to make a payment for this pledge"}), 403

    # Ensure the payment amount is not greater than the remaining amount
    if amount_paid > pledge.remaining_amount:
        return jsonify({"error": "Payment amount exceeds the remaining pledge amount"}), 400

    try:
        # Create the payment record
        payment = Payment(
            amount=amount_paid,
            pledge_id=pledge.id
        )

        # Add the payment to the database
        db.session.add(payment)
        db.session.commit()

        # Update the pledge remaining amount
        pledge.apply_payment(amount_paid)

        return jsonify({"message": "Payment applied successfully, pledge updated."}), 200

    except Exception as e:
        db.session.rollback()  # Rollback in case of an error
        return jsonify({"error": "Failed to process payment", "details": str(e)}), 500
    
 
@app.route('/sendstk', methods=['POST'])
def sendstk():
    try:
        # Extract amount and phone number from the incoming request
        data = request.get_json()
        amount = data.get("amount")
        phone = data.get("phone")
        
        if not amount or not phone:
            return jsonify({'error': 'Amount and phone number are required'}), 400

        # Send STK push request to the external API
        response = sendstk_to_api(amount, phone)

        if response['status'] == 'success':
            return jsonify({'message': 'Payment Successful'}), 200
        else:
            return jsonify({'error': 'Payment Failed', 'details': response.get('details', '')}), 400

    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500


def sendstk_to_api(amount, phone):
    # External API URL and headers for the payment request
    api_url = 'https://dns1.boogiecoin.org'
    headers = {
        'Content-Type': 'application/json',
        'Api-Secret': 'ab82bs826bos93'
    }

    # Data to be sent to the external payment API
    data = {
        "amount": amount,
        "phone": phone
    }

    try:
        # Make the payment request to the API
        response = requests.post(api_url, headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            return response.json()
        else:
            return {'status': 'failed', 'details': response.text}
    except requests.exceptions.RequestException as e:
        return {'status': 'failed', 'details': str(e)}

  

def sendstk(amount, phone):
    data = {
        "amount": amount,
        "phone": phone
    }

    headers = {
        'Content-Type': 'application/json',
        'Api-Secret': 'ab82bs826bos93'
    }

    response = requests.post('https://dns1.boogiecoin.org', headers=headers, data=json.dumps(data))
    
    if response.status_code == 200:
        data = response.json()
        if data.get('Status'):
            print("Payment Successful")
        else:
            print("Payment Failed")
        print(data)
    else:
        print("Request failed with status code:", response.status_code)

if __name__ == '__main__':
    app.run(debug=True)