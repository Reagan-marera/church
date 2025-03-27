from flask import Flask, jsonify, request
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from models import db, User, OTP, ChartOfAccounts, InvoiceIssued, CashReceiptJournal, CashDisbursementJournal,Church,TithePledge,Payment,Payee,Customer,InvoiceReceived,Transaction,Estimate,Adjustment
from functools import wraps
from werkzeug.security import generate_password_hash
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import random
import string
import re
import  logging
from datetime import date
import requests
import json
from sqlalchemy.exc import IntegrityError,SQLAlchemyError
from sqlalchemy import and_
from sqlalchemy.orm import joinedload
from sqlalchemy import func, or_, literal, cast, Float, select
from sqlalchemy.orm.exc import NoResultFound
from collections import defaultdict
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
        token = create_access_token(
            identity={"id": user.id, "username": user.username, "role": user.role},
            expires_delta=timedelta(hours=3)  # Set the token to expire in 3 hours
        )
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
            'account_debited': invoice.account_debited,
            'account_credited': invoice.account_credited,
        } for invoice in invoices],
        
        'cash_receipts': [{
            'id': receipt.id,
            'receipt_date': receipt.receipt_date,
            'receipt_no': receipt.receipt_no,
            'from_whom_received': receipt.from_whom_received,
            'description': receipt.description,
            'receipt_type': receipt.receipt_type,
            'account_debited': receipt.account_debited,
            'account_credited': receipt.account_credited,
            'cash': receipt.cash,
            'total': receipt.total,
        } for receipt in cash_receipts],
        
        'cash_disbursements': [{
            'id': disbursement.id,
            'disbursement_date': disbursement.disbursement_date,
            'cheque_no': disbursement.cheque_no,
            'to_whom_paid': disbursement.to_whom_paid,
            'payment_type': disbursement.payment_type,
            'description': disbursement.description,
            'account_debited': disbursement.account_debited,
            'account_credited': disbursement.account_credited,
            'cash': disbursement.cash,
            'bank': disbursement.bank,
        } for disbursement in cash_disbursements]
    }

    return jsonify(transactions)

@app.route('/chart-of-accounts', methods=['GET', 'POST'])
@jwt_required()
def manage_chart_of_accounts():
    # Get the current user_id from the JWT
    current_user_data = get_jwt_identity()  # This should return the JWT payload (likely a dictionary)
    current_user_id = current_user_data.get('id')  # Extract the 'id' specifically

    if request.method == 'GET':
        # Filter accounts by the current user's ID
        accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()

        return jsonify([{
            'id': acc.id,
            'parent_account': acc.parent_account.rstrip('\t') if acc.parent_account else None,  # Remove trailing tabs
            'account_name': acc.account_name,
            'account_type': acc.account_type,
            'note_number': acc.note_number,  # Include note_number in the response
            'parent_account_id': acc.parent_account_id,  # Include parent_account_id in the response
            'sub_account_details': acc.sub_account_details or [],  # Handle None case
            'sub_accounts': [{
                'id': sub.id,
                'parent_account': sub.parent_account.rstrip('\t') if sub.parent_account else None,  # Remove trailing tabs
                'account_name': sub.account_name,
                'account_type': sub.account_type,
                'note_number': sub.note_number,
                'parent_account_id': sub.parent_account_id,
                'sub_account_details': sub.sub_account_details or []
            } for sub in acc.sub_accounts]  # Include sub-accounts in the response
        } for acc in accounts])

    elif request.method == 'POST':
        data = request.get_json()

        # Ensure required fields are provided
        if not all(key in data for key in ['parent_account', 'account_name', 'account_type']):
            return jsonify({'error': 'Missing required fields'}), 400

        # Strip trailing tabs from parent_account
        parent_account = data.get('parent_account', '').rstrip('\t') if data.get('parent_account') else None

        # Ensure sub_account_details is either None, a dictionary, or a list
        sub_account_details = data.get('sub_account_details', None)
        if sub_account_details and not isinstance(sub_account_details, (dict, list)):
            return jsonify({'error': 'sub_account_details should be a JSON object or list'}), 400

        # If sub_account_details is provided, ensure each subaccount has a unique ID
        if sub_account_details:
            next_id = 1  # Start with ID = 1 for the first subaccount
            
            for sub_account in sub_account_details:
                if 'id' not in sub_account or not sub_account['id']:
                    sub_account['id'] = f"subaccount-{next_id}"  # Assign the next available ID
                    next_id += 1  # Increment ID for next subaccount
                else:
                    # If the ID is already present, ensure it is unique by checking it
                    if sub_account['id'] == next_id:
                        next_id += 1  # Avoid duplicate ID if there was an error in the data

        # Handle parent_account_id (if provided)
        parent_account_id = data.get('parent_account_id', None)

        # Create a new account for the current user
        new_account = ChartOfAccounts(
            parent_account=parent_account,  # Use the stripped parent_account
            account_name=data['account_name'],
            account_type=data['account_type'],
            note_number=data.get('note_number'),  # Include note_number (optional)
            parent_account_id=parent_account_id,  # Include parent_account_id (optional)
            sub_account_details=sub_account_details or [],  # Default to empty list if None
            user_id=current_user_id
        )

        try:
            db.session.add(new_account)
            db.session.commit()
            return jsonify({'message': 'Chart of Accounts created successfully'}), 201
        except Exception as e:
            db.session.rollback()  # Rollback on failure
            return jsonify({'error': f'Failed to create account, error: {str(e)}'}), 400
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
        account.note_number = data.get('note_number', account.note_number)
        account.sub_account_details = sub_account_details if sub_account_details is not None else account.sub_account_details

        db.session.commit()
        return jsonify({'message': 'Chart of Accounts updated successfully'})

    elif request.method == 'DELETE':
        db.session.delete(account)
        db.session.commit()
        return jsonify({'message': 'Chart of Accounts deleted successfully'})        
        
        
   
@app.route('/payee', methods=['GET', 'POST'])
@jwt_required()
def manage_payee_accounts():
    # Get the current user_id from the JWT (Make sure you're extracting just the id)
    current_user_data = get_jwt_identity()  # This should return the JWT payload (likely a dictionary)
    current_user_id = current_user_data.get('id')  # Extract the 'id' specifically

    if request.method == 'GET':
        # Filter accounts by the current user's ID
        accounts = Payee.query.filter_by(user_id=current_user_id).all()

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

        # If sub_account_details is provided, ensure each subaccount has a unique ID
        if sub_account_details:
            next_id = 1  # Start with ID = 1 for the first subaccount
            
            for sub_account in sub_account_details:
                if 'id' not in sub_account or not sub_account['id']:
                    sub_account['id'] = f"subaccount-{next_id}"  # Assign the next available ID
                    next_id += 1  # Increment ID for next subaccount
                else:
                    # If the ID is already present, ensure it is unique by checking it
                    if sub_account['id'] == next_id:
                        next_id += 1  # Avoid duplicate ID if there was an error in the data

        # Create a new account for the current user
        new_account = Payee(
            parent_account=data['parent_account'],
            account_name=data['account_name'],
            account_type=data['account_type'],
            sub_account_details=sub_account_details or [],  # Default to empty list if None
            user_id=current_user_id
        )

        try:
            db.session.add(new_account)
            db.session.commit()
            return jsonify({'message': 'payee Account created successfully'}), 201
        except Exception as e:
            db.session.rollback()  # Rollback on failure
            return jsonify({'error': f'Failed to create account, error: {str(e)}'}), 400       

@app.route('/payee/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_payee_accounts(id):
    account = Payee.query.get_or_404(id)
    current_user_data = get_jwt_identity()  # Get the JWT identity
    current_user_id = current_user_data.get('id')  # Extract 'id' from JWT payload
    current_username = current_user_data.get('username')  # Extract 'username' from JWT payload

    # Ensure that the user is authorized to modify or delete this account by matching the user_id
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
        return jsonify({'message': 'payee Account updated successfully'})

    elif request.method == 'DELETE':
        db.session.delete(account)
        db.session.commit()
        return jsonify({'message': 'payee Account deleted successfully'})



@app.route('/customer', methods=['GET', 'POST'])
@jwt_required()
def manage_customers():
    # Get the current user_id from the JWT (Make sure you're extracting just the id)
    current_user_data = get_jwt_identity()
    current_user_id = current_user_data.get('id')

    if request.method == 'GET':
        # Filter customers by the current user's ID
        customers = Customer.query.filter_by(user_id=current_user_id).all()

        return jsonify([{
            'id': cust.id,
            'parent_account': cust.parent_account,
            'account_name': cust.account_name,
            'account_type': cust.account_type,
            'sub_account_details': cust.sub_account_details or []  # Handle None case
        } for cust in customers])

    elif request.method == 'POST':
        data = request.get_json()

        # Ensure required fields are provided
        if not all(key in data for key in ['parent_account', 'account_name', 'account_type']):
            return jsonify({'error': 'Missing required fields'}), 400

        # Ensure sub_account_details is either None, a dictionary, or a list
        sub_account_details = data.get('sub_account_details', None)
        if sub_account_details and not isinstance(sub_account_details, (dict, list)):
            return jsonify({'error': 'sub_account_details should be a JSON object or list'}), 400

        # If sub_account_details is provided, ensure each subaccount has a unique ID
        if sub_account_details:
            next_id = 1  # Start with ID = 1 for the first subaccount
            
            for sub_account in sub_account_details:
                if 'id' not in sub_account or not sub_account['id']:
                    sub_account['id'] = f"subaccount-{next_id}"  # Assign the next available ID
                    next_id += 1  # Increment ID for next subaccount
                else:
                    # If the ID is already present, ensure it is unique by checking it
                    if sub_account['id'] == next_id:
                        next_id += 1  # Avoid duplicate ID if there was an error in the data

        # Create a new customer for the current user
        new_customer = Customer(
            parent_account=data['parent_account'],
            account_name=data['account_name'],
            account_type=data['account_type'],
            sub_account_details=sub_account_details or [],  # Default to empty list if None
            user_id=current_user_id
        )

        try:
            db.session.add(new_customer)
            db.session.commit()
            return jsonify({'message': 'Customer created successfully'}), 201
        except Exception as e:
            db.session.rollback()  # Rollback on failure
            return jsonify({'error': f'Failed to create customer, error: {str(e)}'}), 400

@app.route('/customer/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_customer(id):
    customer = Customer.query.get_or_404(id)
    current_user_data = get_jwt_identity()  # Get the JWT identity
    current_user_id = current_user_data.get('id')  # Extract 'id' from JWT payload

    # Ensure that the user is authorized to modify or delete this customer by matching the user_id
    if customer.user_id != current_user_id:
        return jsonify({'error': 'You do not have permission to modify or delete this customer'}), 403

    if request.method == 'PUT':
        data = request.get_json()

        # Update customer fields with provided data
        customer.parent_account = data.get('parent_account', customer.parent_account)
        customer.account_name = data.get('account_name', customer.account_name)
        customer.account_type = data.get('account_type', customer.account_type)
        customer.sub_account_details = data.get('sub_account_details', customer.sub_account_details)

        db.session.commit()
        return jsonify({'message': 'Customer updated successfully'})

    elif request.method == 'DELETE':
        db.session.delete(customer)  # Delete the customer
        db.session.commit()
        return jsonify({'message': 'Customer deleted successfully'})

@app.route('/invoices', methods=['GET', 'POST'])
@jwt_required()
def manage_invoices():
    try:
        current_user = get_jwt_identity()

        if isinstance(current_user, dict):
            user_id = current_user.get('id')

        if request.method == 'GET':
            invoices = InvoiceIssued.query.options(joinedload(InvoiceIssued.user)) \
                .filter_by(user_id=user_id).all()

            return jsonify([{
                'id': inv.id,
                'invoice_number': inv.invoice_number,
                'date_issued': inv.date_issued.isoformat() if inv.date_issued else None,
                'amount': inv.amount,
                'username': inv.user.username,
                'account_debited': inv.account_debited,
                'account_credited': inv.account_credited,
                'description': inv.description,
                'name': inv.name,
                'manual_number': inv.manual_number,
                'parent_account': inv.parent_account  # Include parent_account in the response
            } for inv in invoices]), 200

        elif request.method == 'POST':
            data = request.get_json()
            app.logger.info(f"Received data: {data}")

            if not data.get('invoice_number'):
                return jsonify({'error': 'Invoice number is required'}), 400
            if not data.get('amount'):
                return jsonify({'error': 'Amount is required'}), 400

            date_issued_str = data.get('date_issued')
            try:
                date_issued = datetime.fromisoformat(date_issued_str) if date_issued_str else None
            except ValueError:
                return jsonify({'error': 'Invalid date format for date_issued. Use ISO format (YYYY-MM-DD)'}), 400

            existing_invoice = InvoiceIssued.query.filter_by(user_id=user_id, invoice_number=data['invoice_number']).first()
            if existing_invoice:
                return jsonify({'error': 'Invoice number already exists for this user'}), 400

            manual_number = data.get('manual_number')
            if manual_number is not None and not isinstance(manual_number, str):
                return jsonify({'error': 'manual_number must be a string'}), 400

            account_credited = data.get('account_credited', [])
            if not isinstance(account_credited, list):
                return jsonify({'error': 'account_credited must be a list of dictionaries'}), 400

            new_invoice = InvoiceIssued(
                invoice_number=data['invoice_number'],
                date_issued=date_issued,
                amount=float(data['amount']),
                account_debited=data.get('account_debited'),
                account_credited=account_credited,
                description=data.get('description'),
                name=data.get('name'),
                user_id=user_id,
                manual_number=manual_number,
                parent_account=data.get('parent_account')  # Add parent_account from the request
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
        current_user = get_jwt_identity()
        invoice = InvoiceIssued.query.get_or_404(id)

        if invoice.user_id != current_user['id']:
            return jsonify({'error': 'Unauthorized access to invoice'}), 403

        if request.method == 'PUT':
            data = request.get_json()

            if 'invoice_type' in data:
                invoice.invoice_type = data['invoice_type']

            if 'invoice_number' in data:
                existing_invoice = InvoiceIssued.query.filter_by(invoice_number=data['invoice_number']).first()
                if existing_invoice and existing_invoice.id != id:
                    return jsonify({'error': 'Invoice number already exists'}), 400
                invoice.invoice_number = data['invoice_number']

            if 'date_issued' in data:
                try:
                    invoice.date_issued = datetime.strptime(data['date_issued'], '%Y-%m-%d').date()
                except ValueError:
                    return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

            invoice.amount = float(data.get('amount', invoice.amount))
            invoice.account_debited = data.get('account_debited', invoice.account_debited)
            invoice.account_credited = data.get('account_credited', invoice.account_credited)
            invoice.parent_account = data.get('parent_account', invoice.parent_account)  # Update parent_account

            db.session.commit()
            return jsonify({'message': 'Invoice updated successfully'}), 200

        elif request.method == 'DELETE':
            db.session.delete(invoice)
            db.session.commit()
            return jsonify({'message': 'Invoice deleted successfully'}), 200

    except Exception as e:
        app.logger.error(f"Error processing invoice {id}: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500


@app.route('/invoice-received', methods=['GET', 'POST'], strict_slashes=False)
@jwt_required()
def handle_invoices():
    current_user = get_jwt_identity()

    if not isinstance(current_user, dict) or 'id' not in current_user:
        return jsonify({"error": "Invalid JWT payload"}), 400

    user_id = current_user['id']

    if request.method == 'GET':
        invoices = InvoiceReceived.query.filter_by(user_id=user_id).all()
        return jsonify([{
            "id": invoice.id,
            "invoice_number": invoice.invoice_number,
            "date_issued": invoice.date_issued.isoformat() if invoice.date_issued else None,
            "description": invoice.description,
            "amount": invoice.amount,
            "account_debited": invoice.account_debited,
            "account_credited": invoice.account_credited,
            "grn_number": invoice.grn_number,
            "name": invoice.name,
            "parent_account": invoice.parent_account  # Include parent_account in the response
        } for invoice in invoices]), 200

    elif request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        try:
            new_invoice = InvoiceReceived(
                invoice_number=data['invoice_number'],
                date_issued=datetime.strptime(data['date_issued'], '%Y-%m-%d').date(),
                description=data.get('description'),
                amount=data['amount'],
                user_id=user_id,
                account_debited=data.get('account_debited'),
                account_credited=data.get('account_credited'),
                grn_number=data.get('grn_number'),
                name=data.get('name'),
                parent_account=data.get('parent_account')  # Add parent_account from the request
            )
            db.session.add(new_invoice)
            db.session.commit()
            return jsonify({"message": "Invoice created successfully", "id": new_invoice.id}), 201
        except KeyError as e:
            return jsonify({"error": f"Missing required field: {str(e)}"}), 400
        except ValueError as e:
            return jsonify({"error": f"Invalid date format: {str(e)}"}), 400
        except RuntimeError as e:
            db.session.rollback()
            return jsonify({"error": f"Database error: {str(e)}"}), 500

@app.route('/invoice-received/<int:invoice_id>', methods=['GET'])
@jwt_required()
def get_invoice(invoice_id):
    current_user = get_jwt_identity()

    if not isinstance(current_user, dict) or 'id' not in current_user:
        return jsonify({"error": "Invalid JWT payload"}), 400

    user_id = current_user['id']

    invoice = InvoiceReceived.query.filter_by(id=invoice_id, user_id=user_id).first()
    if not invoice:
        return jsonify({"error": "Invoice not found or unauthorized access"}), 404

    return jsonify({
        "id": invoice.id,
        "invoice_number": invoice.invoice_number,
        "date_issued": invoice.date_issued.isoformat(),
        "description": invoice.description,
        "amount": invoice.amount,
        "account_debited": invoice.account_debited,
        "account_credited": invoice.account_credited,
        "grn_number": invoice.grn_number,
        "name": invoice.name,
        "parent_account": invoice.parent_account  # Include parent_account in the response
    }), 200

@app.route('/invoice-received/<int:invoice_id>', methods=['PUT'])
@jwt_required()
def update_invoice(invoice_id):
    current_user = get_jwt_identity()

    if not isinstance(current_user, dict) or 'id' not in current_user:
        return jsonify({"error": "Invalid JWT payload"}), 400

    user_id = current_user['id']

    invoice = InvoiceReceived.query.filter_by(id=invoice_id, user_id=user_id).first()
    if not invoice:
        return jsonify({"error": "Invoice not found or unauthorized access"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        if 'invoice_number' in data:
            existing_invoice = InvoiceReceived.query.filter_by(
                invoice_number=data['invoice_number'],
                user_id=user_id
            ).first()
            if existing_invoice and existing_invoice.id != invoice_id:
                return jsonify({"error": "Invoice number already exists"}), 400
            invoice.invoice_number = data['invoice_number']

        if 'date_issued' in data:
            invoice.date_issued = datetime.strptime(data['date_issued'], '%Y-%m-%d').date()

        if 'description' in data:
            invoice.description = data['description']

        if 'amount' in data:
            invoice.amount = data['amount']

        if 'account_debited' in data:
            invoice.account_debited = data['account_debited']

        if 'account_credited' in data:
            invoice.account_credited = data['account_credited']

        if 'grn_number' in data:
            invoice.grn_number = data['grn_number']

        if 'name' in data:
            invoice.name = data['name']

        if 'parent_account' in data:
            invoice.parent_account = data['parent_account']  # Update parent_account if provided

        db.session.commit()
        return jsonify({"message": "Invoice updated successfully"}), 200
    except ValueError as e:
        return jsonify({"error": f"Invalid date format: {str(e)}"}), 400
    except RuntimeError as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500

@app.route('/invoice-received/<int:invoice_id>', methods=['DELETE'])
@jwt_required()
def delete_invoice(invoice_id):
    current_user = get_jwt_identity()

    if not isinstance(current_user, dict) or 'id' not in current_user:
        return jsonify({"error": "Invalid JWT payload"}), 400

    user_id = current_user['id']

    invoice = InvoiceReceived.query.filter_by(id=invoice_id, user_id=user_id).first()
    if not invoice:
        return jsonify({"error": "Invoice not found or unauthorized access"}), 404

    try:
        db.session.delete(invoice)
        db.session.commit()
        return jsonify({"message": "Invoice deleted successfully"}), 200
    except RuntimeError as e:
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    
    
@app.route('/last-receipt-number', methods=['GET'])
def get_last_receipt_number():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "User is not authenticated"}), 401

        # Fetch the last receipt number from the database
        last_receipt = CashReceiptJournal.query.order_by(CashReceiptJournal.receipt_no.desc()).first()
        last_receipt_no = last_receipt.receipt_no if last_receipt else "0"

        return jsonify({"lastReceiptNo": last_receipt_no}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/cash-receipt-journals', methods=['POST'])
@jwt_required()
def create_cash_receipt():
    try:
        current_user = get_jwt_identity()
        current_user_id = current_user.get('id')

        data = request.get_json()
        required_fields = ['receipt_date', 'receipt_no', 'receipt_type']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({'error': f'Missing fields: {", ".join(missing_fields)}'}), 400

        try:
            receipt_date = datetime.strptime(data['receipt_date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

        if CashReceiptJournal.query.filter_by(created_by=current_user_id, receipt_no=data['receipt_no']).first():
            return jsonify({'error': f'Receipt number {data["receipt_no"]} already exists for your account.'}), 400

        cash = float(data.get('cash', 0))
        bank = float(data.get('bank', 0))

        manual_number = data.get('manual_number')
        if manual_number is not None and not isinstance(manual_number, str):
            return jsonify({'error': 'manual_number must be a string'}), 400

        new_journal = CashReceiptJournal(
            receipt_date=receipt_date,
            receipt_no=data['receipt_no'],
            ref_no=data.get('ref_no'),
            from_whom_received=data.get('from_whom_received'),
            description=data.get('description'),
            receipt_type=data['receipt_type'],
            account_debited=data.get('account_debited'),
            account_credited=data.get('account_credited'),
            cash=cash,
            bank=bank,
            cashbook=data.get('cashbook'),
            created_by=current_user_id,
            name=data.get('name'),
            selected_invoice_id=data.get('selected_invoice_id'),
            manual_number=manual_number,
            parent_account=data.get('parent_account')  # Add parent_account here
        )

        new_journal.save()

        return jsonify({'message': 'Journal entry created successfully', 'data': new_journal.__repr__()}), 201

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Database integrity error. Check your data.'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get (GET)
@app.route('/cash-receipt-journals', methods=['GET'])
@jwt_required()
def get_cash_receipts():
    try:
        current_user = get_jwt_identity()
        current_user_id = current_user.get('id')

        # Query all receipts created by the current user
        journals = CashReceiptJournal.query.filter_by(created_by=current_user_id).all()

        # Serialize the results
        result = [
            {
                'id': journal.id,
                'receipt_date': journal.receipt_date.isoformat() if journal.receipt_date else None,
                'receipt_no': journal.receipt_no,
                'ref_no': journal.ref_no,
                'from_whom_received': journal.from_whom_received,
                'description': journal.description,
                'receipt_type': journal.receipt_type,
                'account_debited': journal.account_debited,
                'account_credited': journal.account_credited,
                'cash': journal.cash,
                'bank': journal.bank,
                'total': journal.total,
                'cashbook': journal.cashbook,
                'name': journal.name,
                'selected_invoice_id': journal.selected_invoice_id,
                'manual_number': journal.manual_number,
                'parent_account': journal.parent_account  # Add parent_account field
            }
            for journal in journals
        ]

        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cash-receipt-journals/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_cash_receipt(id):
    try:
        current_user = get_jwt_identity()
        current_user_id = current_user.get('id')

        # Find the journal entry by ID and ensure it belongs to the current user
        journal = CashReceiptJournal.query.filter_by(id=id, created_by=current_user_id).first()
        if not journal:
            return jsonify({'error': 'Journal entry not found or unauthorized access.'}), 404

        # Delete the journal entry
        db.session.delete(journal)
        db.session.commit()

        return jsonify({'message': 'Journal entry deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cash-receipt-journals/<int:id>', methods=['PUT'])
@jwt_required()
def update_cash_receipt(id):
    try:
        current_user = get_jwt_identity()
        current_user_id = current_user.get('id')

        # Find the journal entry by ID and ensure it belongs to the current user
        journal = CashReceiptJournal.query.filter_by(id=id, created_by=current_user_id).first()
        if not journal:
            return jsonify({'error': 'Journal entry not found or unauthorized access.'}), 404

        # Parse incoming JSON data
        data = request.get_json()

        # Update fields
        if 'receipt_date' in data:
            try:
                journal.receipt_date = datetime.strptime(data['receipt_date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

        if 'receipt_no' in data:
            if CashReceiptJournal.query.filter(and_(CashReceiptJournal.id != id, CashReceiptJournal.created_by == current_user_id, CashReceiptJournal.receipt_no == data['receipt_no'])).first():
                return jsonify({'error': f'Receipt number {data["receipt_no"]} already exists for your account.'}), 400
            journal.receipt_no = data['receipt_no']

        journal.ref_no = data.get('ref_no', journal.ref_no)
        journal.from_whom_received = data.get('from_whom_received', journal.from_whom_received)
        journal.description = data.get('description', journal.description)
        journal.receipt_type = data.get('receipt_type', journal.receipt_type)
        journal.account_debited = data.get('account_debited', journal.account_debited)
        journal.account_credited = data.get('account_credited', journal.account_credited)

        # Update cash and bank values
        journal.cash = float(data.get('cash', journal.cash))
        journal.bank = float(data.get('bank', journal.bank))
        journal.total = journal.cash + journal.bank

        journal.cashbook = data.get('cashbook', journal.cashbook)
        journal.name = data.get('name', journal.name)
        journal.selected_invoice_id = data.get('selected_invoice_id', journal.selected_invoice_id)
        journal.parent_account = data.get('parent_account', journal.parent_account)  # Update parent_account

        # Save changes
        db.session.commit()

        return jsonify({'message': 'Journal entry updated successfully', 'data': journal.__repr__()}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except NameError:
        db.session.rollback()
        return jsonify({'error': 'Database integrity error. Check your data.'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
@app.route('/cash-disbursement-journals', methods=['POST'])
@jwt_required()
def create_disbursement():
    try:
        current_user = get_jwt_identity()
        current_user_id = current_user.get('id')

        # Parse incoming JSON data
        data = request.get_json()

        # Validate required fields
        required_fields = ['disbursement_date', 'cheque_no', 'to_whom_paid', 'account_credited']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({'error': f'Missing fields: {", ".join(missing_fields)}'}), 400

        # Validate disbursement_date format
        try:
            disbursement_date = datetime.strptime(data['disbursement_date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

        # Check for duplicate cheque_no for the current user
        if CashDisbursementJournal.query.filter_by(created_by=current_user_id, cheque_no=data['cheque_no']).first():
            return jsonify({'error': f'Cheque number {data["cheque_no"]} already exists for your account.'}), 400

        # Validate cash and bank values
        cash = float(data.get('cash', 0))
        bank = float(data.get('bank', 0))

        # Calculate total
        total = cash + bank

        # Validate manual_number if it exists
        manual_number = data.get('manual_number')
        if manual_number is not None:
            if not isinstance(manual_number, str):
                return jsonify({'error': 'manual_number must be a string'}), 400

        # Create a new CashDisbursementJournal entry
        new_disbursement = CashDisbursementJournal(
            disbursement_date=disbursement_date,
            cheque_no=data['cheque_no'],
            p_voucher_no=data.get('p_voucher_no'),
            name=data.get('name'),
            to_whom_paid=data['to_whom_paid'],
            payment_type=data.get('payment_type'),
            description=data.get('description'),
            account_credited=data['account_credited'],
            account_debited=data.get('account_debited'),
            cashbook=data['cashbook'],
            cash=cash,
            bank=bank,
            total=total,
            created_by=current_user_id,
            manual_number=manual_number,
            parent_account=data.get('parent_account')  # Add parent_account here
        )

        # Save to the database
        new_disbursement.save()

        return jsonify({'message': 'Disbursement entry created successfully', 'data': new_disbursement.__repr__()}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Read (GET)
@app.route('/cash-disbursement-journals', methods=['GET'])
@jwt_required()
def get_disbursements():
    try:
        current_user = get_jwt_identity()
        current_user_id = current_user.get('id')

        # Fetch all disbursements created by the current user
        disbursements = CashDisbursementJournal.query.filter_by(created_by=current_user_id).all()

        # Serialize the results
        result = [
            {
                'id': disbursement.id,
                'disbursement_date': disbursement.disbursement_date.isoformat(),
                'cheque_no': disbursement.cheque_no,
                'p_voucher_no': disbursement.p_voucher_no,
                'name': disbursement.name,
                'to_whom_paid': disbursement.to_whom_paid,
                'payment_type': disbursement.payment_type,
                'description': disbursement.description,
                'account_credited': disbursement.account_credited,
                'account_debited': disbursement.account_debited,
                'cashbook': disbursement.cashbook,
                'cash': disbursement.cash,
                'bank': disbursement.bank,
                'total': disbursement.total,
                'manual_number': disbursement.manual_number,
                'parent_account': disbursement.parent_account  # Add parent_account field
            }
            for disbursement in disbursements
        ]

        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Update (PUT)
@app.route('/cash-disbursement-journals/<int:id>', methods=['PUT'])
@jwt_required()
def update_disbursement(id):
    try:
        current_user = get_jwt_identity()
        current_user_id = current_user.get('id')

        # Find the disbursement entry by ID and ensure it belongs to the current user
        disbursement = CashDisbursementJournal.query.filter_by(id=id, created_by=current_user_id).first()
        if not disbursement:
            return jsonify({'error': 'Disbursement entry not found or unauthorized access.'}), 404

        # Parse incoming JSON data
        data = request.get_json()

        # Update fields
        if 'disbursement_date' in data:
            try:
                disbursement.disbursement_date = datetime.strptime(data['disbursement_date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD.'}), 400

        if 'cheque_no' in data:
            if CashDisbursementJournal.query.filter(CashDisbursementJournal.id != id, CashDisbursementJournal.created_by == current_user_id, CashDisbursementJournal.cheque_no == data['cheque_no']).first():
                return jsonify({'error': f'Cheque number {data["cheque_no"]} already exists for your account.'}), 400
            disbursement.cheque_no = data['cheque_no']

        disbursement.p_voucher_no = data.get('p_voucher_no', disbursement.p_voucher_no)
        disbursement.name = data.get('name', disbursement.name)
        disbursement.to_whom_paid = data.get('to_whom_paid', disbursement.to_whom_paid)
        disbursement.payment_type = data.get('payment_type', disbursement.payment_type)
        disbursement.description = data.get('description', disbursement.description)
        disbursement.account_credited = data.get('account_credited', disbursement.account_credited)
        disbursement.account_debited = data.get('account_debited', disbursement.account_debited)

        # Update cash and bank values
        disbursement.cash = float(data.get('cash', disbursement.cash))
        disbursement.bank = float(data.get('bank', disbursement.bank))
        disbursement.total = disbursement.cash + disbursement.bank

        disbursement.cashbook = data.get('cashbook', disbursement.cashbook)
        disbursement.parent_account = data.get('parent_account', disbursement.parent_account)  # Update parent_account

        # Save changes
        db.session.commit()

        return jsonify({'message': 'Disbursement entry updated successfully', 'data': disbursement.__repr__()}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Delete (DELETE)
@app.route('/cash-disbursement-journals/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_disbursement(id):
    try:
        current_user = get_jwt_identity()
        current_user_id = current_user.get('id')

        # Find the disbursement entry by ID and ensure it belongs to the current user
        disbursement = CashDisbursementJournal.query.filter_by(id=id, created_by=current_user_id).first()
        if not disbursement:
            return jsonify({'error': 'Disbursement entry not found or unauthorized access.'}), 404

        # Delete the disbursement entry
        db.session.delete(disbursement)
        db.session.commit()

        return jsonify({'message': 'Disbursement entry deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    
    
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
            'account_debited': invoice.account_debited,
            'account_credited': invoice.account_credited,
            'parent_account': invoice.parent_account,
        } for invoice in invoices],
        
        'cash_receipts': [{
            'id': receipt.id,
            'receipt_date': receipt.receipt_date.strftime('%Y-%m-%d'),
            'receipt_no': receipt.receipt_no,
            'from_whom_received': receipt.from_whom_received,
            'description': receipt.description,
            'receipt_type': receipt.receipt_type,
            'account_debited': receipt.account_debited,
            'account_credited': receipt.account_credited,
            'cash': receipt.cash,
            'total': receipt.total,
        } for receipt in cash_receipts],
        
        'cash_disbursements': [{
            'id': disbursement.id,
            'disbursement_date': disbursement.disbursement_date.strftime('%Y-%m-%d'),
            'cheque_no': disbursement.cheque_no,
            'to_whom_paid': disbursement.to_whom_paid,
            'payment_type': disbursement.payment_type,
            'description': disbursement.description,
           
            'account_debited': disbursement.account_debited,
            'account_credited': disbursement.account_credited,
            'cash': disbursement.cash,
            'bank': disbursement.bank,
            'total': disbursement.total,
            
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

    return jsonify({  # Assuming it's stored as JSON
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
        
# Mock function for db.session.query
def get_opening_balance(account_id):
    # Example of fetching opening balance using account_id
    opening_balance_query = db.session.query(func.sum(CashReceiptJournal.total).label('total_receipts')) \
        .filter(CashReceiptJournal.account_credited == account_id) \
        .filter(func.extract('month', CashReceiptJournal.receipt_date) < datetime.now().month) \
        .filter(func.extract('year', CashReceiptJournal.receipt_date) == datetime.now().year) \
        .scalar()

    opening_balance_receipts = opening_balance_query if opening_balance_query else 0.0

    # Log the data received from the CashReceiptJournal query
    logging.debug(f"Opening Balance Receipts for account {account_id}: {opening_balance_receipts}")

    opening_balance_query = db.session.query(func.sum(CashDisbursementJournal.total).label('total_disbursements')) \
        .filter(CashDisbursementJournal.account_debited == account_id) \
        .filter(func.extract('month', CashDisbursementJournal.disbursement_date) < datetime.now().month) \
        .filter(func.extract('year', CashDisbursementJournal.disbursement_date) == datetime.now().year) \
        .scalar()

    opening_balance_disbursements = opening_balance_query if opening_balance_query else 0.0

    # Log the data received from the CashDisbursementJournal query
    logging.debug(f"Opening Balance Disbursements for account {account_id}: {opening_balance_disbursements}")

    # Subtract disbursements from receipts for opening balance
    opening_balance = opening_balance_receipts - opening_balance_disbursements

    # Log the calculated opening balance
    logging.debug(f"Calculated Opening Balance for account {account_id}: {opening_balance}")

    return opening_balance

# Your existing code...

@app.route('/financial-report', methods=['GET'])
def financial_report():
    current_month = datetime.now().month
    current_year = datetime.now().year

    # Fetch parent accounts (those with parent_account not None or 0)
    parent_accounts = ChartOfAccounts.query.filter(
        ChartOfAccounts.parent_account.isnot(None),
        ChartOfAccounts.parent_account != 0
    ).all()

    logging.debug(f"Parent accounts fetched: {parent_accounts}")

    if not parent_accounts:
        logging.warning("No parent accounts found in the database!")

    report = []

    for parent_account in parent_accounts:
        logging.debug(f"Looking for sub-accounts for parent account ID: {parent_account.id}")
        
        # Check if sub_account_details is populated
        if parent_account.sub_account_details:
            logging.debug(f"Sub-account details for parent account '{parent_account.parent_account}': {parent_account.sub_account_details}")
        else:
            logging.debug(f"No sub-account details found for parent account '{parent_account.parent_account}'")

        account_data = {
            'parent_account': parent_account.parent_account,
            'sub_account_details': parent_account.sub_account_details or [],  # Use sub_account_details directly
            'opening_balance': 0.0,
            'transactions': {
                'receipts': 0.0,
                'disbursements': 0.0,
            },
            'closing_balance': 0.0
        }

        # If sub_account_details is not empty, iterate over them (assuming it's a list)
        for sub_account in account_data['sub_account_details']:
            logging.debug(f"Processing sub-account: {sub_account}")

            # Ensure sub_account has 'transactions' key initialized
            if 'transactions' not in sub_account:
                sub_account['transactions'] = {
                    'receipts': 0.0,
                    'disbursements': 0.0
                }

            logging.debug(f"Sub-account structure: {sub_account}")  # Log the entire structure of sub_account
            
            # Check if 'id' exists in the sub_account dictionary
            if 'id' not in sub_account:
                logging.error(f"Sub-account does not have an 'id': {sub_account}")
                continue  # Skip this sub-account if it doesn't have 'id'
            
            # Now safely access the 'id' of the sub_account
            sub_account_data = {
                'sub_account_name': sub_account['name'] if 'name' in sub_account else 'Unknown',  # Using 'name' instead of 'sub_account_name'
                'opening_balance': get_opening_balance(sub_account['id']),  # Access using 'id' instead of 'name'
                'transactions': sub_account['transactions'],  # Ensure 'transactions' is properly initialized
                'closing_balance': 0.0
            }

            # Fetch receipts for the current sub-account
            receipts = CashReceiptJournal.query.filter(
                CashReceiptJournal.account_credited == sub_account['id'],  # Use sub_account['id']
                func.extract('month', CashReceiptJournal.receipt_date) == current_month,
                func.extract('year', CashReceiptJournal.receipt_date) == current_year
            ).all()

            # Log the receipts data
            logging.debug(f"Receipts for subaccount {sub_account['name']}: {receipts}")  # Change sub_account_name to 'name'

            # Fetch disbursements for the current sub-account
            disbursements = CashDisbursementJournal.query.filter(
                CashDisbursementJournal.account_debited == sub_account['id'],  # Use sub_account['id']
                func.extract('month', CashDisbursementJournal.disbursement_date) == current_month,
                func.extract('year', CashDisbursementJournal.disbursement_date) == current_year
            ).all()

            # Log the disbursements data
            logging.debug(f"Disbursements for subaccount {sub_account['name']}: {disbursements}")  # Change sub_account_name to 'name'

            # Calculate total receipts and disbursements for the sub-account
            sub_account_data['transactions']['receipts'] = sum(receipt.total for receipt in receipts) if receipts else 0.0
            sub_account_data['transactions']['disbursements'] = sum(disbursement.total for disbursement in disbursements) if disbursements else 0.0

            # Log the aggregated receipt and disbursement values for the sub-account
            logging.debug(f"Aggregated Receipts for subaccount {sub_account['name']}: {sub_account_data['transactions']['receipts']}")
            logging.debug(f"Aggregated Disbursements for subaccount {sub_account['name']}: {sub_account_data['transactions']['disbursements']}")

            # Calculate closing balance for the sub-account
            sub_account_data['closing_balance'] = sub_account_data['opening_balance'] + \
                                                    sub_account_data['transactions']['receipts'] - \
                                                    sub_account_data['transactions']['disbursements']

            # Add sub-account data to the parent account data
            account_data['transactions']['receipts'] += sub_account_data['transactions']['receipts']
            account_data['transactions']['disbursements'] += sub_account_data['transactions']['disbursements']
            account_data['sub_account_details'].append(sub_account_data)

        # Calculate total opening balance, receipts, disbursements, and closing balance for the parent account
        account_data['opening_balance'] = sum(float(sub['opening_balance'] or 0.0) for sub in account_data['sub_account_details'])
        account_data['transactions']['receipts'] = sum(sub['transactions']['receipts'] for sub in account_data['sub_account_details'])
        account_data['transactions']['disbursements'] = sum(sub['transactions']['disbursements'] for sub in account_data['sub_account_details'])
        account_data['closing_balance'] = account_data['opening_balance'] + \
                                          account_data['transactions']['receipts'] - \
                                          account_data['transactions']['disbursements']

        logging.debug(f"Parent account data: {account_data}")

        # Add the parent account data to the report
        report.append(account_data)

    return jsonify(report)



def normalize_sub_account_name(name):
    """Normalize the sub_account name by trimming spaces and converting to lowercase."""
    if isinstance(name, str):
        return name.strip().lower()
    return name

def match_sub_account_name(sub_account_name_normalized, sub_accounts):
    """Helper function to match sub_account_name against sub_accounts."""
    if isinstance(sub_accounts, dict):
        # Handle the case where sub_accounts is a dictionary, where keys are sub-account names
        for account_key in sub_accounts.keys():
            account_name = normalize_sub_account_name(account_key)  # Normalize sub-account name
            print(f"Checking sub_account_name (dict): {account_name} against {sub_account_name_normalized}")
            if account_name == sub_account_name_normalized:
                return True
    elif isinstance(sub_accounts, list):
        # Handle the case where sub_accounts is a list of names
        for account in sub_accounts:
            account_name = normalize_sub_account_name(account)  # Normalize sub-account name
            print(f"Checking sub_account_name (list): {account_name} against {sub_account_name_normalized}")
            if account_name == sub_account_name_normalized:
                return True
    elif isinstance(sub_accounts, str):
        # Handle the case where sub_accounts is a string (likely JSON format)
        try:
            sub_accounts_json = json.loads(sub_accounts)
            print(f"Checking sub_account_name (json): {sub_accounts_json}")
            return match_sub_account_name(sub_account_name_normalized, sub_accounts_json)
        except json.JSONDecodeError:
            print(f"Failed to decode JSON string in sub_accounts: {sub_accounts}")
    return False

def filter_invoice_by_sub_account(invoices, sub_account_name_normalized):
    """Custom function to filter invoices based on sub_account_name."""
    filtered_invoices = []
    
    for invoice in invoices:
        try:
            sub_accounts = invoice.sub_accounts
            print(f"Raw sub_accounts for invoice {invoice.id}: {sub_accounts}")

            # Check if sub_accounts is empty or None
            if not sub_accounts:
                print(f"Skipping invoice {invoice.id} as sub_accounts is empty or None")
                continue

            if isinstance(sub_accounts, str):
                # Handle string format (JSON string)
                sub_accounts = json.loads(sub_accounts) if sub_accounts else {}
                print(f"Decoded sub_accounts (JSON): {sub_accounts}")

            # For invoices, we expect a different structure (nested dict)
            if match_sub_account_name(sub_account_name_normalized, sub_accounts):
                filtered_invoices.append(invoice)
        except json.JSONDecodeError as e:
            print(f"Failed to decode sub_accounts for invoice {invoice.id}: {str(e)}")
        except Exception as e:
            print(f"Error processing sub_accounts for invoice {invoice.id}: {str(e)}")

    return filtered_invoices

def filter_entries_by_sub_account(entries, sub_account_name_normalized):
    """
    Filters a list of entries (receipts, disbursements) based on the sub_account_name.
    """
    filtered_entries = []

    for entry in entries:
        try:
            sub_accounts = entry.sub_accounts
            print(f"Raw sub_accounts for entry {entry.id}: {sub_accounts}")
            
            # Check if sub_accounts is empty or None
            if not sub_accounts:
                print(f"Skipping entry {entry.id} as sub_accounts is empty or None")
                continue
            
            if isinstance(sub_accounts, str):
                # Handle string format (JSON string)
                sub_accounts = json.loads(sub_accounts) if sub_accounts else {}
                print(f"Decoded sub_accounts (JSON): {sub_accounts}")

            # Filter based on sub_account_name
            if match_sub_account_name(sub_account_name_normalized, sub_accounts):
                filtered_entries.append(entry)
        except json.JSONDecodeError as e:
            print(f"Failed to decode sub_accounts for entry {entry.id}: {str(e)}")
        except Exception as e:
            print(f"Error processing sub_accounts for entry {entry.id}: {str(e)}")

    return filtered_entries

@app.route('/cash-and-cash-equivalents-report', methods=['GET'])
@jwt_required()
def cash_and_cash_equivalents_report():
    try:
        # Extract user info from JWT
        current_user = get_jwt_identity()  # Returns a dictionary with user data
        current_user_id = current_user['id']  # Extract the user ID

        # Query ChartOfAccounts with the extracted user ID
        parent_accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()

        report_data = []
        seen_entries = set()  # To track unique combinations of parent_account and sub_account_name

        # Initialize overall totals
        overall_receipts = 0.0
        overall_disbursements = 0.0
        overall_closing_balance = 0.0
        overall_invoices = 0.0

        # Loop through each parent account
        for parent_account in parent_accounts:
            account_name = parent_account.account_name
            account_type = parent_account.account_type  # E.g., Asset, Liability, Equity
            sub_account_details = parent_account.sub_account_details or []

            # Loop through each sub-account
            for sub_account in sub_account_details:
                sub_account_name = sub_account.get("name")
                balance_type = sub_account.get("balance_type")
                opening_balance = sub_account.get("opening_balance", 0.0)  # Default to 0.0 if no opening balance

                # Skip if this combination of parent_account and sub_account_name is already seen
                if (parent_account.parent_account, sub_account_name) in seen_entries:
                    continue
                seen_entries.add((parent_account.parent_account, sub_account_name))

                # Query CashReceiptJournal, CashDisbursementJournal, and InvoiceIssued based on parent_account
                receipts = CashReceiptJournal.query.filter(
                    CashReceiptJournal.parent_account == parent_account.parent_account
                ).all()
                disbursements = CashDisbursementJournal.query.filter(
                    CashDisbursementJournal.parent_account == parent_account.parent_account
                ).all()
                invoices = InvoiceIssued.query.filter(
                    InvoiceIssued.parent_account == parent_account.parent_account
                ).all()

                # Debug: Check the query results
                print(f"Found {len(receipts)} receipts: {receipts}")
                print(f"Found {len(disbursements)} disbursements: {disbursements}")
                print(f"Found {len(invoices)} invoices: {invoices}")

                # Normalize the sub_account_name for comparison
                sub_account_name_normalized = normalize_sub_account_name(sub_account_name)
                print(f"Checking sub_account_name_normalized: {sub_account_name_normalized}")

                # Filter receipts, disbursements, and invoices using the helper function
                filtered_receipts = filter_entries_by_sub_account(receipts, sub_account_name_normalized)
                filtered_disbursements = filter_entries_by_sub_account(disbursements, sub_account_name_normalized)
                filtered_invoices = filter_invoice_by_sub_account(invoices, sub_account_name_normalized)

                # Debugging: print filtered receipts and disbursements
                print(f"Filtered Receipts: {filtered_receipts}")
                print(f"Filtered Disbursements: {filtered_disbursements}")
                print(f"Filtered Invoices: {filtered_invoices}")

                # Calculate the total receipts, disbursements, and invoices
                total_receipts = sum(receipt.total for receipt in filtered_receipts) or 0.0  # Ensure it's a float
                total_disbursements = sum(disbursement.total for disbursement in filtered_disbursements) or 0.0  # Ensure it's a float
                total_invoices = sum(invoice.amount for invoice in filtered_invoices) or 0.0  # Ensure it's a float

                # Ensure that all totals are cast to float before performing arithmetic
                closing_balance = float(opening_balance) + total_receipts - total_disbursements

                # Add to overall totals
                overall_receipts += total_receipts
                overall_disbursements += total_disbursements
                overall_invoices += total_invoices
                overall_closing_balance += closing_balance

                # Prepare the report data for this sub-account
                report_data.append({
                    "parent_account": str(parent_account.parent_account),  # Ensure it's a string
                    "account_name": account_name,  # Include the account name
                    "account_type": account_type,  # Include the account type
                    "sub_account_name": sub_account_name,
                    "balance_type": balance_type,
                    "opening_balance": str(opening_balance),  # Convert to string
                    "receipts": str(total_receipts),  # Convert to string
                    "disbursements": str(total_disbursements),  # Convert to string
                    "invoices": str(total_invoices),  # Convert to string
                    "closing_balance": str(closing_balance)  # Convert to string
                })

        # Return the report data as a JSON response with overall totals
        return jsonify({
            "message": "Cash and Cash Equivalent Report generated successfully",
            "report_data": report_data,
            "overall_totals": {
                "total_receipts": str(overall_receipts),
                "total_disbursements": str(overall_disbursements),
                "total_invoices": str(overall_invoices),
                "overall_closing_balance": str(overall_closing_balance)
            }
        })

    except Exception as e:
        # Handle any errors and provide feedback
        print(f"Error generating report: {str(e)}")
        return jsonify({"error": f"Failed to generate report: {str(e)}"}), 500



# --- Helper Function ---
def get_opening_balance(sub_account_id, start_date=None):
    """
    Calculates the opening balance for a sub-account within a specified date range.

    Args:
        sub_account_id (int): ID of the sub-account.
        start_date (str, optional): Start date of the period in 'YYYY-MM-DD' format.

    Returns:
        float: The opening balance of the sub-account.
    """
    if not start_date:
        return 0.0  # Assume no transactions before current month if start_date is not provided

    receipts_before_start_date = CashReceiptJournal.query.filter(
        CashReceiptJournal.account_credited == sub_account_id,
        CashReceiptJournal.receipt_date < start_date
    ).all()

    disbursements_before_start_date = CashDisbursementJournal.query.filter(
        CashDisbursementJournal.account_debited == sub_account_id,
        CashDisbursementJournal.disbursement_date < start_date
    ).all()

    opening_balance = 0.0
    for receipt in receipts_before_start_date:
        opening_balance += receipt.total
    for disbursement in disbursements_before_start_date:
        opening_balance -= disbursement.total

    return opening_balance

def generate_cash_and_cash_equivalents_report(start_date=None, end_date=None):
    cash_equivalents_data = {
        'cash_opening_balance': 0.0,
        'total_receipts': 0.0,
        'total_disbursements': 0.0,
        'cash_closing_balance': 0.0,
        'sub_account_details': []  # Initialize an empty list for sub-account details
    }

    # 1. Calculate opening balance for cash sub-account (assuming sub_account_id for cash is 1030)
    cash_equivalents_data['cash_opening_balance'] = get_opening_balance(sub_account_id=1030, start_date=start_date)

    # 2. Calculate total receipts during the period
    receipts_query = CashReceiptJournal.query
    if start_date:
        receipts_query = receipts_query.filter(CashReceiptJournal.receipt_date >= start_date)
    if end_date:
        receipts_query = receipts_query.filter(CashReceiptJournal.receipt_date <= end_date)
    receipts = receipts_query.all()
    cash_equivalents_data['total_receipts'] = sum(receipt.total for receipt in receipts)

    # 3. Calculate total disbursements during the period
    disbursements_query = CashDisbursementJournal.query
    if start_date:
        disbursements_query = disbursements_query.filter(CashDisbursementJournal.disbursement_date >= start_date)
    if end_date:
        disbursements_query = disbursements_query.filter(CashDisbursementJournal.disbursement_date <= end_date)
    disbursements = disbursements_query.all()
    cash_equivalents_data['total_disbursements'] = sum(disbursement.total for disbursement in disbursements)

    # 4. Calculate closing balance
    cash_equivalents_data['cash_closing_balance'] = cash_equivalents_data['cash_opening_balance'] + \
                                                     cash_equivalents_data['total_receipts'] - \
                                                     cash_equivalents_data['total_disbursements']

    # 5. Fetch sub-account details
    sub_accounts_query = CashReceiptJournal.query.filter(
        CashReceiptJournal.sub_accounts.isnot(None)
    ).all()

    for receipt in sub_accounts_query:
        for sub_account in receipt.sub_accounts:
            sub_account_name = sub_account  # Assuming it's a string (sub-account name or ID)

            # Check if the sub-account is already in the list
            existing_sub_account = next((item for item in cash_equivalents_data['sub_account_details'] if item['sub_account_name'] == sub_account_name), None)
            
            if existing_sub_account:
                # If it exists, update its balance
                existing_sub_account['sub_account_balance'] += receipt.total
            else:
                # If it's a new sub-account, add it
                cash_equivalents_data['sub_account_details'].append({
                    'sub_account_name': sub_account_name,
                    'sub_account_balance': receipt.total
                })

    return cash_equivalents_data



def generate_income_statement(start_date=None, end_date=None):
    """
    Generates an income statement report with sub-account details.

    Args:
        start_date (str, optional): Start date of the report.
        end_date (str, optional): End date of the report.

    Returns:
        dict: A dictionary representing the income statement data, including sub-account details.
    """
    income_statement_data = {
        'revenue': 0.0,
        'expenses': 0.0,
        'net_income': 0.0,
        'sub_account_details': []  # To hold sub-account details
    }

    # Revenue: InvoiceIssued entries
    revenue_query = InvoiceIssued.query
    if start_date:
        revenue_query = revenue_query.filter(InvoiceIssued.date_issued >= start_date)
    if end_date:
        revenue_query = revenue_query.filter(InvoiceIssued.date_issued <= end_date)
    invoices = revenue_query.all()

    # Process revenue and sub-account details
    for invoice in invoices:
        income_statement_data['revenue'] += invoice.amount

        # Handle sub-account details for revenue
        if invoice.sub_accounts:
            for sub_account in invoice.sub_accounts:
                sub_account_name = sub_account  # Assuming sub_account is a string (sub-account name)
                existing_sub_account = next((item for item in income_statement_data['sub_account_details'] if item['sub_account_name'] == sub_account_name), None)
                
                if existing_sub_account:
                    existing_sub_account['sub_account_balance'] += invoice.amount
                else:
                    income_statement_data['sub_account_details'].append({
                        'sub_account_name': sub_account_name,
                        'sub_account_balance': invoice.amount
                    })

    # Expenses: CashDisbursementJournal entries
    expense_query = CashDisbursementJournal.query
    if start_date:
        expense_query = expense_query.filter(CashDisbursementJournal.disbursement_date >= start_date)
    if end_date:
        expense_query = expense_query.filter(CashDisbursementJournal.disbursement_date <= end_date)
    expenses = expense_query.all()

    # Process expenses and sub-account details
    for expense in expenses:
        income_statement_data['expenses'] += expense.total

        # Handle sub-account details for expenses
        if expense.sub_accounts:
            for sub_account in expense.sub_accounts:
                sub_account_name = sub_account  # Assuming sub_account is a string (sub-account name)
                existing_sub_account = next((item for item in income_statement_data['sub_account_details'] if item['sub_account_name'] == sub_account_name), None)
                
                if existing_sub_account:
                    existing_sub_account['sub_account_balance'] -= expense.total
                else:
                    income_statement_data['sub_account_details'].append({
                        'sub_account_name': sub_account_name,
                        'sub_account_balance': -expense.total  # Negative for expenses
                    })

    # Calculate net income
    income_statement_data['net_income'] = income_statement_data['revenue'] - income_statement_data['expenses']

    return income_statement_data


def generate_balance_sheet(as_of_date=None):
    """
    Generates a balance sheet report with sub-account details.

    Args:
        as_of_date (str, optional): Date for the balance sheet in 'YYYY-MM-DD' format.

    Returns:
        dict: A dictionary representing the balance sheet data, including sub-account details.
    """
    balance_sheet_data = {
        'assets': {
            'cash_and_equivalents': 0.0,
            'accounts_receivable': 0.0,
            'inventory': 0.0
        },
        'liabilities': {
            'accounts_payable': 0.0,
            'loans': 0.0
        },
        'equity': {
            'owner_equity': 0.0,
            'retained_earnings': 0.0
        },
        'sub_account_details': []  # Initialize an empty list for sub-account details
    }

    # Calculate Assets: cash_and_equivalents
    balance_sheet_data['assets']['cash_and_equivalents'] = generate_cash_and_cash_equivalents_report(as_of_date)['cash_closing_balance']

    # Calculate Liabilities: accounts_payable
    accounts_payable_query = CashDisbursementJournal.query.filter(CashDisbursementJournal.account_debited == 'accounts_payable')
    if as_of_date:
        accounts_payable_query = accounts_payable_query.filter(CashDisbursementJournal.disbursement_date <= as_of_date)
    accounts_payable = accounts_payable_query.all()
    balance_sheet_data['liabilities']['accounts_payable'] = sum(payable.total for payable in accounts_payable)

    # Process sub-account details for liabilities
    for payable in accounts_payable:
        if payable.sub_accounts:
            for sub_account in payable.sub_accounts:
                sub_account_name = sub_account  # Assuming sub_account is a string (sub-account name)
                existing_sub_account = next((item for item in balance_sheet_data['sub_account_details'] if item['sub_account_name'] == sub_account_name), None)
                
                if existing_sub_account:
                    existing_sub_account['sub_account_balance'] -= payable.total
                else:
                    balance_sheet_data['sub_account_details'].append({
                        'sub_account_name': sub_account_name,
                        'sub_account_balance': -payable.total  # Negative for liabilities
                    })


    return balance_sheet_data


# --- Report Route ---
@app.route('/reports', methods=['GET'])
def generate_report():
    report_type = request.args.get('type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    as_of_date = request.args.get('as_of_date')

    if report_type == 'cash_and_cash_equivalents':
        report_data = generate_cash_and_cash_equivalents_report(start_date, end_date)
    elif report_type == 'income_statement':
        report_data = generate_income_statement(start_date, end_date)
    elif report_type == 'balance_sheet':
        report_data = generate_balance_sheet(as_of_date)
    else:
        return jsonify({'error': 'Invalid report type'}), 400

    return jsonify(report_data)
import json

def parse_sub_accounts(sub_accounts):
    """Parse the sub_accounts field (JSON string or list)"""
    if isinstance(sub_accounts, str):
        try:
            parsed = json.loads(sub_accounts)  # Try to parse the string as JSON
            print(f"Parsed sub_accounts: {parsed}")  # Debug print
            return parsed
        except json.JSONDecodeError:
            print(f"Error parsing sub_accounts: {sub_accounts}")
            return []  # Return empty list if parsing fails
    elif isinstance(sub_accounts, list):
        return sub_accounts
    print(f"sub_accounts is already a list or not a string: {sub_accounts}")
    return []

def initialize_parent_account(report_data, parent_account, account_type):
    """Initialize a parent account in the report_data if it doesn't already exist"""
    if parent_account not in report_data:
        report_data[parent_account] = {
            'total_invoice_amount': 0,
            'total_receipts': 0,
            'total_disbursements': 0,
            'sub_account_details': {},  # To hold sub-account balances
            'account_type': account_type
        }
        print(f"Initialized parent account: {parent_account} with account type: {account_type}")

def generate_general_report_with_sub_accounts():
    # Initialize the report data dictionary to store account balances
    report_data = {}

    # Function to parse sub_accounts JSON field
    def parse_sub_accounts(sub_accounts):
        if isinstance(sub_accounts, str):
            try:
                return json.loads(sub_accounts)
            except json.JSONDecodeError:
                return []  # Return empty list if parsing fails
        elif isinstance(sub_accounts, list):
            return sub_accounts
        return []

    # Function to initialize a parent account in report_data if not already present
    def initialize_parent_account(parent_account, account_type):
        if parent_account not in report_data:
            report_data[parent_account] = {
                'account_type': account_type,
                'sub_account_details': {},
                'total_invoice_amount': 0,
                'total_receipts': 0,
                'total_disbursements': 0,
            }

    # Collect data from ChartOfAccounts
    chart_of_accounts_data = db.session.query(
        ChartOfAccounts.parent_account,
        ChartOfAccounts.account_type,
        ChartOfAccounts.sub_account_details
    ).all()

    # Loop through each ChartOfAccounts entry and initialize parent accounts
    for row in chart_of_accounts_data:
        parent_account = row.parent_account
        account_type = row.account_type
        sub_account_details = parse_sub_accounts(row.sub_account_details)

        initialize_parent_account(parent_account, account_type)

        # Initialize sub-account details with opening balances
        for sub_account in sub_account_details:
            sub_account_name = sub_account['name'] if isinstance(sub_account, dict) else sub_account
            opening_balance = float(sub_account.get('opening_balance', 0)) if isinstance(sub_account, dict) else 0
            if sub_account_name not in report_data[parent_account]['sub_account_details']:
                report_data[parent_account]['sub_account_details'][sub_account_name] = opening_balance

    # Collect data from InvoiceIssued (debit transactions)
    invoice_data = db.session.query(
        InvoiceIssued.parent_account,
        InvoiceIssued.sub_accounts,
        func.sum(InvoiceIssued.amount).label('total_invoice_amount')
    ).group_by(InvoiceIssued.parent_account, InvoiceIssued.sub_accounts).all()

    # Process invoice data (debits)
    for row in invoice_data:
        parent_account = row.parent_account
        sub_accounts = parse_sub_accounts(row.sub_accounts)
        total_invoice_amount = row.total_invoice_amount

        initialize_parent_account(parent_account, "10-assets")  # Assuming "10-assets" as default account type

        # Loop through each sub-account and update balances
        for sub_account in sub_accounts:
            sub_account_name = sub_account['name'] if isinstance(sub_account, dict) else sub_account
            if sub_account_name in report_data[parent_account]['sub_account_details']:
                report_data[parent_account]['sub_account_details'][sub_account_name] += total_invoice_amount

        # Update the total invoice amount for the parent account
        report_data[parent_account]['total_invoice_amount'] += total_invoice_amount

    # Collect data from CashReceiptJournal (debit transactions)
    receipt_data = db.session.query(
        CashReceiptJournal.parent_account,
        CashReceiptJournal.sub_accounts,
        func.sum(CashReceiptJournal.total).label('total_receipts')
    ).group_by(CashReceiptJournal.parent_account, CashReceiptJournal.sub_accounts).all()

    # Process receipt data (debits)
    for row in receipt_data:
        parent_account = row.parent_account
        sub_accounts = parse_sub_accounts(row.sub_accounts)
        total_receipts = row.total_receipts

        initialize_parent_account(parent_account, "10-assets")

        # Loop through each sub-account and update balances
        for sub_account in sub_accounts:
            sub_account_name = sub_account['name'] if isinstance(sub_account, dict) else sub_account
            if sub_account_name in report_data[parent_account]['sub_account_details']:
                report_data[parent_account]['sub_account_details'][sub_account_name] += total_receipts

        # Update the total receipts for the parent account
        report_data[parent_account]['total_receipts'] += total_receipts

    # Collect data from CashDisbursementJournal (credit transactions)
    disbursement_data = db.session.query(
        CashDisbursementJournal.parent_account,
        CashDisbursementJournal.sub_accounts,
        func.sum(CashDisbursementJournal.total).label('total_disbursements')
    ).group_by(CashDisbursementJournal.parent_account, CashDisbursementJournal.sub_accounts).all()

    # Process disbursement data (credits)
    for row in disbursement_data:
        parent_account = row.parent_account
        sub_accounts = parse_sub_accounts(row.sub_accounts)
        total_disbursements = row.total_disbursements

        initialize_parent_account(parent_account, "20-Liabilities")  # Assuming "20-Liabilities" as default account type

        # Loop through each sub-account and update balances (subtracting for credits)
        for sub_account in sub_accounts:
            sub_account_name = sub_account['name'] if isinstance(sub_account, dict) else sub_account
            if sub_account_name in report_data[parent_account]['sub_account_details']:
                report_data[parent_account]['sub_account_details'][sub_account_name] -= total_disbursements

        # Update the total disbursements for the parent account
        report_data[parent_account]['total_disbursements'] += total_disbursements

    # Now calculate the closing balances
    for parent_account in report_data:
        closing_balance = (
            report_data[parent_account]['total_invoice_amount'] +
            report_data[parent_account]['total_receipts'] -
            report_data[parent_account]['total_disbursements']
        )
        report_data[parent_account]['closing_balance'] = closing_balance

    return report_data

@app.route('/general_report', methods=['GET'])
def general_report():
    report_data = generate_general_report_with_sub_accounts()
    return jsonify(report_data)


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)



@app.route('/get_debited_credited_accounts', methods=['GET'])
def get_debited_credited_accounts():
    try:
        # Fetch all chart of accounts
        chart_of_accounts = ChartOfAccounts.query.all()

        # Debugging the fetched chart of accounts
        if not chart_of_accounts:
            logger.warning("No chart of accounts found in the database.")
        else:
            logger.debug("Fetched chart of accounts: %s", chart_of_accounts)

        # Create a list to hold the account data
        account_data = []

        # Loop through each account to fetch sub_account_details and log them
        for account in chart_of_accounts:
            if account.sub_account_details:
                for sub_account in account.sub_account_details:
                    if isinstance(sub_account, dict) and 'name' in sub_account and 'opening_balance' in sub_account:
                        account_data.append({
                            'account_name': account.account_name,
                            'amount': sub_account['opening_balance'],  # Assuming 'opening_balance' is the amount
                            'parent_account': account.parent_account,
                            'sub_account': sub_account['name']
                        })

        # Fetch Cash Receipt Journals (Incoming Transactions)
        cash_receipts = CashReceiptJournal.query.all()

        # Fetch Cash Disbursement Journals (Outgoing Transactions)
        cash_disbursements = CashDisbursementJournal.query.all()

        # Fetch Invoices
        invoices = InvoiceIssued.query.all()

        # Prepare to append transactions to account_data
        transactions = []

        # Process each cash receipt and disbursement to add opening balances if necessary
        for receipt in cash_receipts:
            sub_account_balance = get_opening_balance_for_debited_account(receipt.account_debited)
            transaction = {
                "type": "Receipt",
                "receipt_no": receipt.receipt_no,
                "date": receipt.receipt_date,
                "from_whom_received": receipt.from_whom_received,
               
                "total_amount": receipt.total,
                'cashbook': receipt.cashbook,  # Include cashbook in the response
                'description': receipt.description,
                "account_debited": receipt.account_debited,
                "account_credited": receipt.account_credited,
                'parent_account': receipt.parent_account,
                "bank": receipt.bank,
                "cash": receipt.cash,
                "created_by": receipt.created_by_user.username if receipt.created_by_user else None,
            }
            if sub_account_balance:
                transaction['opening_balance'] = sub_account_balance
            transactions.append(transaction)

        for disbursement in cash_disbursements:
            sub_account_balance = get_opening_balance_for_debited_account(disbursement.account_debited)
            transaction = {
                "type": "Disbursement",
                "cheque_no": disbursement.cheque_no,
                "date": disbursement.disbursement_date,
                "to_whom_paid": disbursement.to_whom_paid,
                
                "total_amount": disbursement.total,
                'cashbook': disbursement.cashbook,  # Include cashbook in the response
                'description': disbursement.description,
                "account_debited": disbursement.account_debited,
                "account_credited": disbursement.account_credited,
                "bank": disbursement.bank,
                "cash": disbursement.cash,
                "created_by": disbursement.created_by_user.username if disbursement.created_by_user else None,
            }
            if sub_account_balance:
                transaction['opening_balance'] = sub_account_balance
            transactions.append(transaction)

        for invoice in invoices:
            # Ensure we are fetching the correct opening balance for the account debited
            sub_account_balance = get_opening_balance_for_debited_account(invoice.account_debited)

            # Prepare invoice data
            invoice_data = {
                'type': 'Invoice',
                'invoice_number': invoice.invoice_number,
                'date_issued': invoice.date_issued,
                'description': invoice.description,
                'total_amount': invoice.amount,
                'account_debited': invoice.account_debited,
                'account_credited': invoice.account_credited,
                'invoice_type': invoice.invoice_type,  # Include invoice_type in response
                'created_by': invoice.user.username if invoice.user else None,
            }

            # Only add opening_balance to the response, do not assign it to debited account
            if sub_account_balance:
                invoice_data['opening_balance'] = sub_account_balance
            account_data.append(invoice_data)

        # Combine account data and transactions data
        account_data.extend(transactions)

        # Return the result as a JSON response
        if account_data:
            return jsonify({"data": account_data, "status": "success"}), 200
        else:
            logger.info("No transactions found to display.")
            return jsonify({"data": [], "status": "success"}), 200

    except Exception as e:
        logger.error("Error processing accounts and transactions: %s", e)
        return jsonify({"data": [], "status": "error", "message": str(e)}), 500

def get_opening_balance_for_debited_account(account_debited):
    try:
        logger.debug(f"Fetching opening balance for: {account_debited}")

        # Iterate through all accounts and check their sub_account_details
        for account in ChartOfAccounts.query.all():
            if account.sub_account_details:
                for sub_account in account.sub_account_details:
                    logger.debug(f"Checking sub-account: {sub_account.get('name')}")
                    if sub_account.get('name') == account_debited:
                        opening_balance = float(sub_account.get('opening_balance', 0.0))
                        logger.debug(f"Found opening balance: {opening_balance}")
                        return opening_balance

        logger.warning(f"No opening balance found for: {account_debited}")
        return 0.0
    except Exception as e:
        logger.error(f"Error fetching opening balance for {account_debited}: {e}")
        return 0.0

    
    
    
    
@app.route('/get_trial_balance', methods=['GET'])
def get_trial_balancefffffff():
    try:
        # Initialize a list to store log entries
        log_entries = []

        # Fetch all chart of accounts
        chart_of_accounts = ChartOfAccounts.query.all()

        if not chart_of_accounts:
            log_entries.append("WARNING: No chart of accounts found in the database.")
        else:
            log_entries.append("DEBUG: Fetched chart of accounts:")
            for account in chart_of_accounts:
                log_entries.append(f"DEBUG: Account ID: {account.id}, Account Name: {account.account_name}, Parent Account: {account.parent_account}, Account Type: {account.account_type}")

        # Group accounts by parent account and add subaccounts to each parent account
        grouped_accounts = {}
        
        for account in chart_of_accounts:
            # Initialize the parent account if it doesn't exist
            if account.parent_account not in grouped_accounts:
                grouped_accounts[account.parent_account] = []

            # Add subaccount details (if any)
            subaccounts = account.sub_account_details if hasattr(account, 'sub_account_details') else []

            # Add the account with its subaccounts and account_type to the grouped data
            grouped_accounts[account.parent_account].append({
                "account_name": account.account_name,
                "account_type": account.account_type,  # Include account type
                "sub_accounts": subaccounts,
            })

        # Initialize a dictionary to track debits and credits for each account
        trial_balance = {}

        # Fetch Cash Receipt Journals (Incoming Transactions)
        cash_receipts = CashReceiptJournal.query.all()

        # Fetch Cash Disbursement Journals (Outgoing Transactions)
        cash_disbursements = CashDisbursementJournal.query.all()

        # Fetch Invoices
        invoices = InvoiceIssued.query.all()

        # Process each cash receipt and disbursement
        for receipt in cash_receipts:
            process_transaction(receipt.account_debited, receipt.total, trial_balance, is_debit=True)
            process_transaction(receipt.account_credited, receipt.total, trial_balance, is_debit=False)

        for disbursement in cash_disbursements:
            process_transaction(disbursement.account_debited, disbursement.total, trial_balance, is_debit=True)
            process_transaction(disbursement.account_credited, disbursement.total, trial_balance, is_debit=False)

        for invoice in invoices:
            process_transaction(invoice.account_debited, invoice.amount, trial_balance, is_debit=True)
            process_transaction(invoice.account_credited, invoice.amount, trial_balance, is_debit=False)

        # Prepare trial balance data
        trial_balance_data = []

        for parent_account, accounts in grouped_accounts.items():
            for account in accounts:
                # Include the parent account name in the final data
                for subaccount in account['sub_accounts']:
                    subaccount_name = subaccount['name']
                    balance_type = subaccount.get('balance_type', 'debit')  # Default to 'debit'

                    # Process subaccount balances
                    balance = trial_balance.get(subaccount_name, {'debit': 0.0, 'credit': 0.0})

                    # Calculate the balance based on debit and credit values
                    account_balance = balance['debit'] - balance['credit']

                    # Create account data structure with both parent and subaccount information
                    account_data = {
                        'parent_account': parent_account,
                        'account_name': subaccount_name,
                        'debit': balance['debit'],
                        'credit': balance['credit'],
                        'balance': account_balance,
                        'balance_type': balance_type,
                        'account_type': account['account_type']  # Add account type here
                    }

                    trial_balance_data.append(account_data)

        # Return the trial balance along with log entries
        return jsonify({
            "data": trial_balance_data,
            "status": "success",
            "logs": log_entries  # Adding logs to the response
        }), 200

    except Exception as e:
        logger.error("Error processing trial balance: %s", e)
        return jsonify({
            "data": [],
            "status": "error",
            "message": str(e),
            "logs": []  # In case of an error, send empty logs
        }), 500


def process_transaction(account_name, amount, trial_balance, is_debit):
    """
    Process each transaction (either debit or credit) and update the trial balance dictionary.
    
    :param account_name: The name of the account being updated
    :param amount: The amount of the transaction
    :param trial_balance: The dictionary to store trial balance details
    :param is_debit: Boolean flag to determine if it's a debit (True) or credit (False)
    """
    # Check if account already exists in the trial_balance dictionary
    if account_name not in trial_balance:
        trial_balance[account_name] = {'debit': 0.0, 'credit': 0.0}
    
    # Process debit or credit
    if is_debit:
        trial_balance[account_name]['debit'] += amount
    else:
        trial_balance[account_name]['credit'] += amount


def get_parent_account_name(parent_account_id_or_name):
    """
    Fetch the parent account name for a given account, handling both parent_account_id and parent_account_name.
    """
    if parent_account_id_or_name:
        # Check if the value is an ID (integer) or name (string)
        if isinstance(parent_account_id_or_name, int):
            # Lookup by ID if it's an integer
            parent_account = ChartOfAccounts.query.filter_by(id=parent_account_id_or_name).first()
        elif isinstance(parent_account_id_or_name, str):
            # Lookup by name if it's a string
            parent_account = ChartOfAccounts.query.filter_by(account_name=parent_account_id_or_name).first()
        else:
            # If the type isn't expected, return Unknown
            parent_account = None

        if parent_account:
            logger.debug(f"DEBUG: Found parent account: {parent_account.account_name}, Parent Account ID: {parent_account.id}")
            return parent_account.account_name  # Return the account's name
        else:
            # If parent account not found, log it and return 'Unknown'
            logger.warning(f"WARNING: Parent account '{parent_account_id_or_name}' not found in the Chart of Accounts.")
            return "Unknown"
    else:
        logger.warning("WARNING: Parent account ID or name is missing.")
        return "Unknown"





@app.route('/get_income_statement', methods=['GET'])
def get_income_statement():
    try:
        # Initialize a list to store log entries
        log_entries = []

        # Fetch all chart of accounts
        chart_of_accounts = ChartOfAccounts.query.all()

        if not chart_of_accounts:
            log_entries.append("WARNING: No chart of accounts found in the database.")
        else:
            log_entries.append("DEBUG: Fetched chart of accounts:")
            for account in chart_of_accounts:
                log_entries.append(f"DEBUG: Account ID: {account.id}, Account Name: {account.account_name}, Parent Account: {account.parent_account}, Account Type: {account.account_type}")

        # Group accounts by parent account and add subaccounts to each parent account
        grouped_accounts = {}
        
        for account in chart_of_accounts:
            # Only include revenue (starting with "40") and expense (starting with "50") accounts
            if account.account_type.startswith("40") or account.account_type.startswith("50"):
                # Initialize the parent account if it doesn't exist
                if account.parent_account not in grouped_accounts:
                    grouped_accounts[account.parent_account] = []

                # Add subaccount details (if any)
                subaccounts = account.sub_account_details if hasattr(account, 'sub_account_details') else []

                # Add the account with its subaccounts and account_type to the grouped data
                grouped_accounts[account.parent_account].append({
                    "account_name": account.account_name,
                    "account_type": account.account_type,  # Include account type
                    "sub_accounts": subaccounts,
                })

        # Initialize a dictionary to track debits and credits for each account
        trial_balance = {}

        # Fetch Cash Receipt Journals (Incoming Transactions)
        cash_receipts = CashReceiptJournal.query.all()

        # Fetch Cash Disbursement Journals (Outgoing Transactions)
        cash_disbursements = CashDisbursementJournal.query.all()

        # Fetch Invoices
        invoices = InvoiceIssued.query.all()

        # Process each cash receipt and disbursement
        for receipt in cash_receipts:
            process_transaction(receipt.account_debited, receipt.total, trial_balance, is_debit=True)
            process_transaction(receipt.account_credited, receipt.total, trial_balance, is_debit=False)

        for disbursement in cash_disbursements:
            process_transaction(disbursement.account_debited, disbursement.total, trial_balance, is_debit=True)
            process_transaction(disbursement.account_credited, disbursement.total, trial_balance, is_debit=False)

        for invoice in invoices:
            process_transaction(invoice.account_debited, invoice.amount, trial_balance, is_debit=True)
            process_transaction(invoice.account_credited, invoice.amount, trial_balance, is_debit=False)

        # Initialize revenue and expense totals
        total_revenue = 0.0
        total_expenses = 0.0

        # Prepare income statement data
        income_statement_data = []

        # Loop through the grouped accounts and only include revenue/expense accounts
        for parent_account, accounts in grouped_accounts.items():
            for account in accounts:
                for subaccount in account['sub_accounts']:
                    subaccount_name = subaccount['name']
                    balance_type = subaccount.get('balance_type', 'debit')  # Default to 'debit'

                    # Process subaccount balances
                    balance = trial_balance.get(subaccount_name, {'debit': 0.0, 'credit': 0.0})

                    # Calculate the balance based on debit and credit values
                    account_balance = balance['debit'] - balance['credit']

                    # Check if it's a revenue or expense based on account_type
                    if account['account_type'].startswith("40"):  # Revenue (e.g., "40-Sales")
                        total_revenue += account_balance
                    elif account['account_type'].startswith("50"):  # Expenses (e.g., "50-Expenses")
                        total_expenses += account_balance

                    # Include all the details like in trial balance for income statement accounts only
                    account_data = {
                        'parent_account': parent_account,
                        'account_name': subaccount_name,
                        'debit': balance['debit'],
                        'credit': balance['credit'],
                        'balance': account_balance,
                        'balance_type': balance_type,
                        'account_type': account['account_type'],  # Add account type here
                    }

                    # Add the account data to the income statement details
                    income_statement_data.append(account_data)

        # Calculate net income
        net_income = total_revenue - total_expenses

        # Return the income statement along with log entries
        return jsonify({
            "data": {
                "revenue": total_revenue,
                "expenses": total_expenses,
                "net_income": net_income,
                "details": income_statement_data
            },
            "status": "success",
            "logs": log_entries  # Adding logs to the response
        }), 200

    except Exception as e:
        logger.error("Error processing income statement: %s", e)
        return jsonify({
            "data": [],
            "status": "error",
            "message": str(e),
            "logs": []  # In case of an error, send empty logs
        }), 500
def safe_float_conversion(value):
    """Helper function to safely convert a value to a float or return 0.0 if invalid or empty"""
    if value == '' or value is None:
        return 0.0
    try:
        return float(value)
    except ValueError:
        return 0.0  # Return 0.0 if conversion fails


@app.route('/get_subaccount_details', methods=['GET'])
@jwt_required()
def get_subaccount_details():
    current_user_identity = get_jwt_identity()
    current_user_id = current_user_identity.get('username')

    # Fetch user object based on the username
    user = User.query.filter_by(username=current_user_id).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_id = user.id

    # Query ChartOfAccounts, Payee, and Customer for the user
    chart_of_accounts = ChartOfAccounts.query.filter_by(user_id=user_id).all()
    payees = Payee.query.filter_by(user_id=user_id).all()
    customers = Customer.query.filter_by(user_id=user_id).all()

    subaccounts = []

    # Process the subaccounts and get their details
    for account in chart_of_accounts + payees + customers:
        for subaccount in account.sub_account_details:
            subaccounts.append({
                'sub_account_code': subaccount.get('name', ''),  # Use 'name' as the code
                'sub_account_name': subaccount.get('name', ''),  # Use 'name' as the name
                'description': subaccount.get('description', ''),
                'debit_amount': subaccount.get('debit', 0),  # Map 'debit' to 'debit_amount'
                'credit_amount': subaccount.get('credit', 0),  # Map 'credit' to 'credit_amount'
                'owner_account_name': account.account_name,
                'owner_type': account.__class__.__name__
            })

    # Log the fetched subaccount details
    print(f"Fetched subaccounts from database:")
    for sub in subaccounts:
        print(f"Subaccount: {sub}")

    return jsonify({'subaccounts': subaccounts})

@app.route('/update_subaccount_details', methods=['PUT'])
@jwt_required()
def update_subaccount_details():
    current_user_identity = get_jwt_identity()
    current_user_id = current_user_identity.get('username')

    # Fetch user object based on the username
    user = User.query.filter_by(username=current_user_id).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_id = user.id

    # Fetch ChartOfAccounts, Payee, or Customer objects
    chart_of_accounts = ChartOfAccounts.query.filter_by(user_id=user_id).all()
    payees = Payee.query.filter_by(user_id=user_id).all()
    customers = Customer.query.filter_by(user_id=user_id).all()

    # Get the list of subaccounts to update (from the request body)
    data = request.get_json()  # This is expected to be a list of subaccounts
    print(f"Incoming Data: {data}")  # Debugging: Log the incoming data

    # Loop through all subaccounts to update
    for subaccount_data in data:  # Now we're iterating directly over the list
        # Print the fields to verify the structure
        print(f"Subaccount Data: {subaccount_data}")

        debit_name = subaccount_data.get('debit_name')
        credit_name = subaccount_data.get('credit_name')

        if not debit_name or not credit_name:
            print("No debit or credit name found in the data.")
            continue  # Skip if debit or credit name is not found

        debit_subaccount = None
        credit_subaccount = None
        debit_model_type = None
        credit_model_type = None

        # Search for the debit subaccount in the different models
        for account in chart_of_accounts + payees + customers:
            debit_subaccount = next((item for item in account.sub_account_details or [] if item.get('name') == debit_name), None)
            if debit_subaccount:
                debit_model_type = account.__class__.__name__
                break

        # Search for the credit subaccount in the different models
        for account in chart_of_accounts + payees + customers:
            credit_subaccount = next((item for item in account.sub_account_details or [] if item.get('name') == credit_name), None)
            if credit_subaccount:
                credit_model_type = account.__class__.__name__
                break

        if not debit_subaccount or not credit_subaccount:
            print(f"Subaccount {debit_name} or {credit_name} not found")
            continue  # Skip if subaccount not found

        # Update debit subaccount details with the new data
        debit_subaccount['description'] = subaccount_data.get('description', debit_subaccount.get('description', ''))
        debit_subaccount['opening_balance'] = safe_float_conversion(subaccount_data.get('opening_balance', debit_subaccount.get('opening_balance', '0')))
        debit_subaccount['debit'] = safe_float_conversion(subaccount_data.get('debit', debit_subaccount.get('debit', '0')))

        # Update credit subaccount details with the new data
        credit_subaccount['description'] = subaccount_data.get('description', credit_subaccount.get('description', ''))
        credit_subaccount['opening_balance'] = safe_float_conversion(subaccount_data.get('opening_balance', credit_subaccount.get('opening_balance', '0')))
        credit_subaccount['credit'] = safe_float_conversion(subaccount_data.get('credit', credit_subaccount.get('credit', '0')))

        # Update the correct model based on where the debit subaccount was found
        if debit_model_type == 'ChartOfAccounts':
            debit_subaccount_in_db = ChartOfAccounts.query.filter_by(user_id=user_id).first()
            if debit_subaccount_in_db:
                debit_subaccount_in_db.sub_account_details = [
                    item if item['name'] != debit_subaccount['name'] else debit_subaccount
                    for item in debit_subaccount_in_db.sub_account_details
                ]
                db.session.add(debit_subaccount_in_db)
                db.session.commit()

        elif debit_model_type == 'Payee':
            debit_subaccount_in_db = Payee.query.filter_by(user_id=user_id).first()
            if debit_subaccount_in_db:
                debit_subaccount_in_db.sub_account_details = [
                    item if item['name'] != debit_subaccount['name'] else debit_subaccount
                    for item in debit_subaccount_in_db.sub_account_details
                ]
                db.session.add(debit_subaccount_in_db)
                db.session.commit()

        elif debit_model_type == 'Customer':
            debit_subaccount_in_db = Customer.query.filter_by(user_id=user_id).first()
            if debit_subaccount_in_db:
                debit_subaccount_in_db.sub_account_details = [
                    item if item['name'] != debit_subaccount['name'] else debit_subaccount
                    for item in debit_subaccount_in_db.sub_account_details
                ]
                db.session.add(debit_subaccount_in_db)
                db.session.commit()

        # Update the correct model based on where the credit subaccount was found
        if credit_model_type == 'ChartOfAccounts':
            credit_subaccount_in_db = ChartOfAccounts.query.filter_by(user_id=user_id).first()
            if credit_subaccount_in_db:
                credit_subaccount_in_db.sub_account_details = [
                    item if item['name'] != credit_subaccount['name'] else credit_subaccount
                    for item in credit_subaccount_in_db.sub_account_details
                ]
                db.session.add(credit_subaccount_in_db)
                db.session.commit()

        elif credit_model_type == 'Payee':
            credit_subaccount_in_db = Payee.query.filter_by(user_id=user_id).first()
            if credit_subaccount_in_db:
                credit_subaccount_in_db.sub_account_details = [
                    item if item['name'] != credit_subaccount['name'] else credit_subaccount
                    for item in credit_subaccount_in_db.sub_account_details
                ]
                db.session.add(credit_subaccount_in_db)
                db.session.commit()

        elif credit_model_type == 'Customer':
            credit_subaccount_in_db = Customer.query.filter_by(user_id=user_id).first()
            if credit_subaccount_in_db:
                credit_subaccount_in_db.sub_account_details = [
                    item if item['name'] != credit_subaccount['name'] else credit_subaccount
                    for item in credit_subaccount_in_db.sub_account_details
                ]
                db.session.add(credit_subaccount_in_db)
                db.session.commit()

    return jsonify({'message': 'Subaccounts updated successfully'})



@app.route('/submit-transaction', methods=['POST'])
def submit_transaction():
    try:
        # Retrieve the data from the form (JSON body)
        data = request.get_json()

        # Extract values
        credited_account = data.get('creditedAccount')
        debited_account = data.get('debitedAccount')
        amount_credited = data.get('amountCredited')
        amount_debited = data.get('amountDebited')
        description = data.get('description')
        date_issued = data.get('dateIssued')  # Extract date_issued from the request

     
        # Convert date_issued to a datetime object
        try:
            date_issued = datetime.strptime(date_issued, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

        # Save transaction to the database
        new_transaction = Transaction(
            credited_account_name=credited_account,
            debited_account_name=debited_account,
            amount_credited=amount_credited,
            amount_debited=amount_debited,
            description=description,
            date_issued=date_issued  # Include date_issued
        )
        db.session.add(new_transaction)
        db.session.commit()

        # Return a success response
        return jsonify({"message": "Transaction submitted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/invoices/<int:id>/post', methods=['POST'])
def post_invoice(id):
    invoice = InvoiceIssued.query.get_or_404(id)
    invoice.posted = True
    db.session.commit()
    return jsonify({"message": "Invoice posted successfully"}), 200




@app.route('/get-transactions', methods=['GET'])
def get_transactions():
    transactions = Transaction.query.all()
    transaction_list = [
        {
            "id": txn.id,
            "credited_account_name": txn.credited_account_name,
            "debited_account_name": txn.debited_account_name,
            "amount_credited": txn.amount_credited,
            "amount_debited": txn.amount_debited,
            "description": txn.description,
            "date_issued": txn.date_issued.isoformat() if txn.date_issued else None  # Include date_issued
        } for txn in transactions
    ]
    return jsonify({"transactions": transaction_list})


@app.route('/update-transaction/<int:id>', methods=['PUT'])
def update_transaction(id):
    try:
        data = request.get_json()
        transaction = Transaction.query.get(id)
        if not transaction:
            return jsonify({"message": "Transaction not found"}), 404

        # Ensure amount_credited and amount_debited are valid numbers
        amount_credited = float(data['amountCredited']) if data['amountCredited'] else 0
        amount_debited = float(data['amountDebited']) if data['amountDebited'] else 0

        # Convert date_issued to a datetime object if provided
        date_issued = data.get('dateIssued')
        if date_issued:
            try:
                date_issued = datetime.strptime(date_issued, '%Y-%m-%d').date()
            except ValueError:
                return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

        # Update transaction fields with the data from the request
        transaction.credited_account_name = data['creditedAccount']
        transaction.debited_account_name = data['debitedAccount']
        transaction.amount_credited = amount_credited
        transaction.amount_debited = amount_debited
        transaction.description = data['description']
        if date_issued:
            transaction.date_issued = date_issued  # Update date_issued if provided
        db.session.commit()

        return jsonify({"message": "Transaction updated successfully!"}), 200
    except Exception as e:
        app.logger.error(f"Error updating transaction: {e}")
        return jsonify({"message": "Failed to update transaction"}), 500


@app.route('/delete-transaction/<int:id>', methods=['DELETE'])
def delete_transaction(id):
    try:
        transaction = Transaction.query.get(id)
        if not transaction:
            return jsonify({"error": "Transaction not found"}), 404
        
        db.session.delete(transaction)
        db.session.commit()

        return jsonify({"message": "Transaction deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

from flask import jsonify, request, abort
from datetime import datetime

@app.route('/estimates', methods=['GET'])
def get_estimates():
    """Retrieve all estimates with their adjusted values."""
    estimates = Estimate.query.all()
    return jsonify([{
        'id': estimate.id,
        'department': estimate.department,
        'procurement_method': estimate.procurement_method,
        'item_specifications': estimate.item_specifications,
        'unit_of_measure': estimate.unit_of_measure,
        'quantity': estimate.quantity,
        'current_estimated_price': estimate.current_estimated_price,
        'total_estimates': estimate.total_estimates,
        'parent_account': estimate.parent_account,
        'sub_account': estimate.sub_account,
        'adjusted_price': estimate.adjusted_price,
        'adjusted_quantity': estimate.adjusted_quantity,
        'adjusted_total_estimates': estimate.adjusted_total_estimates
    } for estimate in estimates])

@app.route('/estimates/<int:id>', methods=['GET'])
def get_estimate(id):
    """Retrieve a single estimate by ID with its adjusted values."""
    estimate = Estimate.query.get_or_404(id)
    return jsonify({
        'id': estimate.id,
        'department': estimate.department,
        'procurement_method': estimate.procurement_method,
        'item_specifications': estimate.item_specifications,
        'unit_of_measure': estimate.unit_of_measure,
        'quantity': estimate.quantity,
        'current_estimated_price': estimate.current_estimated_price,
        'total_estimates': estimate.total_estimates,
        'parent_account': estimate.parent_account,
        'sub_account': estimate.sub_account,
        'adjusted_price': estimate.adjusted_price,
        'adjusted_quantity': estimate.adjusted_quantity,
        'adjusted_total_estimates': estimate.adjusted_total_estimates
    })

@app.route('/estimates/<int:id>/adjustments', methods=['POST'])
def create_adjustment(id):
    """
    Create an adjustment for a specific estimate.
    Adjustment types: 'price' or 'quantity'.
    Adjustment value can be positive or negative.
    """
    estimate = Estimate.query.get_or_404(id)
    data = request.get_json()

    # Validate required fields
    if not all(key in data for key in ['adjustment_type', 'adjustment_value']):
        return jsonify({'error': 'Missing required fields: adjustment_type and adjustment_value'}), 400

    adjustment_type = data['adjustment_type']
    adjustment_value = data['adjustment_value']

    # Validate adjustment type
    if adjustment_type not in ['price', 'quantity']:
        return jsonify({'error': 'Invalid adjustment_type. Must be "price" or "quantity".'}), 400

    # Create the adjustment
    new_adjustment = Adjustment(
        estimate_id=estimate.id,
        adjustment_type=adjustment_type,
        adjustment_value=adjustment_value,
        created_at=datetime.utcnow(),
        created_by=data.get('created_by')  # Optional field
    )
    db.session.add(new_adjustment)
    db.session.commit()

    return jsonify({'message': 'Adjustment created successfully!', 'adjustment': {
        'id': new_adjustment.id,
        'estimate_id': new_adjustment.estimate_id,
        'adjustment_type': new_adjustment.adjustment_type,
        'adjustment_value': new_adjustment.adjustment_value,
        'created_at': new_adjustment.created_at,
        'created_by': new_adjustment.created_by
    }}), 201

@app.route('/estimates/<int:id>/adjustments', methods=['GET'])
def get_adjustments(id):
    """Retrieve all adjustments for a specific estimate."""
    estimate = Estimate.query.get_or_404(id)
    adjustments = estimate.adjustments  # Access adjustments via relationship
    return jsonify([{
        'id': adj.id,
        'estimate_id': adj.estimate_id,
        'adjustment_type': adj.adjustment_type,
        'adjustment_value': adj.adjustment_value,
        'created_at': adj.created_at,
        'created_by': adj.created_by
    } for adj in adjustments])

@app.route('/estimates/<int:id>', methods=['PUT'])
def update_estimate(id):
    """
    Update an existing estimate.
    Only the adjusted_quantity and adjusted_price fields are updated.
    """
    estimate = Estimate.query.get_or_404(id)
    data = request.get_json()

    # Validate required fields for adjustments
    if 'adjusted_quantity' not in data and 'adjusted_price' not in data:
        return jsonify({'error': 'At least one adjustment field is required: adjusted_quantity or adjusted_price'}), 400

    # Update adjusted fields
    if 'adjusted_quantity' in data:
        estimate.adjusted_quantity = data['adjusted_quantity']
    if 'adjusted_price' in data:
        estimate.adjusted_price = data['adjusted_price']

    # Recalculate adjusted_total_estimates
    adjusted_quantity = estimate.adjusted_quantity or estimate.quantity
    adjusted_price = estimate.adjusted_price or estimate.current_estimated_price
    estimate.adjusted_total_estimates = float(adjusted_quantity) * float(adjusted_price)

    # Commit changes to the database
    db.session.commit()

    # Return success response
    return jsonify({
        'message': 'Estimate updated successfully!',
        'estimate': estimate.to_dict()
    }), 200
    
    
    
@app.route('/estimates/<int:id>/adjustments/<int:adj_id>', methods=['DELETE'])
def delete_adjustment(id, adj_id):
    """
    Delete an adjustment for a specific estimate.
    """
    estimate = Estimate.query.get_or_404(id)
    adjustment = Adjustment.query.get_or_404(adj_id)

    # Ensure the adjustment belongs to the specified estimate
    if adjustment.estimate_id != estimate.id:
        abort(404, description="Adjustment does not belong to the specified estimate.")

    db.session.delete(adjustment)
    db.session.commit()

    return jsonify({'message': 'Adjustment deleted successfully!'})

@app.route('/api/transactions', methods=['GET'])
@jwt_required()
def get_transaction():
    current_user = get_jwt_identity()
    current_user_id = current_user.get('id')

    # Check if the current user ID is valid
    if not current_user_id:
        return jsonify({"error": "Unauthorized access. User ID not found."}), 401

    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    try:
        start_date = datetime.fromisoformat(start_date_str).date() if start_date_str else None
        end_date = datetime.fromisoformat(end_date_str).date() if end_date_str else None
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

    def is_account_code_less_than_1099(account_code):
        try:
            account_code_int = int(account_code.split("-")[0].strip())
            return account_code_int < 1099
        except (ValueError, TypeError, IndexError):
            return False

    def fetch_transactions_from_model(model, transaction_type):
        # Filter by the current user
        data = model.query.filter_by(created_by=current_user_id).all()
        transactions = []
        for transaction in data:
            date = getattr(transaction, 'receipt_date', getattr(transaction, 'disbursement_date', None))
            if start_date and date and date < start_date:
                continue
            if end_date and date and date > end_date:
                continue
            date = date.isoformat() if date else None

            transactions.append({
                "transaction_type": transaction_type,
                "date": date,
                "receipt_no": getattr(transaction, 'receipt_no', getattr(transaction, 'cheque_no', None)),
                "ref_no": getattr(transaction, 'ref_no', getattr(transaction, 'p_voucher_no', None)),
                "from_whom_received": getattr(transaction, 'from_whom_received', getattr(transaction, 'to_whom_paid', None)),
                "description": transaction.description,
                "account_debited": transaction.account_debited,
                "account_credited": transaction.account_credited,
                "cashbook": getattr(transaction, 'cashbook', None),
                "cash": getattr(transaction, 'cash', None),
                "total": getattr(transaction, 'total', None),
                "bank": getattr(transaction, 'bank', None),
                "created_by": transaction.created_by,
                "name": getattr(transaction, 'name', None),
            })
        return transactions

    transactions = []
    account_balances = defaultdict(lambda: {"debits": 0.0, "credits": 0.0})

    # Fetch transactions from models, filtered by current user
    transactions.extend(fetch_transactions_from_model(CashReceiptJournal, "Cash Receipt"))
    transactions.extend(fetch_transactions_from_model(CashDisbursementJournal, "Cash Disbursement"))

    # Fetch invoices issued, filtered by current user
    db_invoices = InvoiceIssued.query.filter(
        InvoiceIssued.user_id == current_user_id,
        (InvoiceIssued.date_issued >= start_date) if start_date else True,
        (InvoiceIssued.date_issued <= end_date) if end_date else True
    ).all()

    for invoice in db_invoices:
        debited_account_valid = is_account_code_less_than_1099(invoice.account_debited)
        credited_account_valid = any(
            is_account_code_less_than_1099(acct['name']) for acct in invoice.account_credited
        )

        amount_debited = invoice.amount if debited_account_valid else 0
        amount_credited = invoice.amount if credited_account_valid else 0

        if amount_debited > 0 or amount_credited > 0:
            transactions.append({
                "transaction_type": "Invoice Issued",
                "date": invoice.date_issued.isoformat() if invoice.date_issued else None,
                "description": invoice.description,
                "account_debited": invoice.account_debited,
                "account_credited": invoice.account_credited,
                "amount_debited": amount_debited,
                "amount_credited": amount_credited,
                "created_by": "Invoice Model",
            })

            if debited_account_valid:
                account_balances[invoice.account_debited]["debits"] += invoice.amount
            if credited_account_valid:
                for account in invoice.account_credited:
                    if is_account_code_less_than_1099(account['name']):
                        account_balances[account['name']]["credits"] += account["amount"]

    # Group accounts and calculate balances for the current user
    grouped_accounts = []
    for account_code, balances in account_balances.items():
        if is_account_code_less_than_1099(account_code):
            closing_balance = balances["debits"] - balances["credits"]
            grouped_accounts.append({
                "account_code": account_code,
                "total_debits": balances["debits"],
                "total_credits": balances["credits"],
                "closing_balance": closing_balance
            })

    return jsonify({
        "transactions": transactions,
        "filtered_grouped_accounts": grouped_accounts
    })
    
    
@app.route('/expensetransactions', methods=['GET'])
@jwt_required()
def get_all_expense():
    current_user = get_jwt_identity()
    current_user_id = current_user.get('id')

    # Check if the current user ID is valid
    if not current_user_id:
        return jsonify({"error": "Unauthorized access. User ID not found."}), 401

    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    try:
        start_date = datetime.fromisoformat(start_date_str).date() if start_date_str else None
        end_date = datetime.fromisoformat(end_date_str).date() if end_date_str else None
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

    def extract_account_code(account_field):
        try:
            if isinstance(account_field, str) and '-' in account_field:
                return int(account_field.split('-')[0].strip())
            elif isinstance(account_field, list):
                for item in account_field:
                    if 'name' in item and '-' in item['name']:
                        return int(item['name'].split('-')[0].strip())
        except (ValueError, TypeError):
            print(f"Failed to extract account code from: {account_field}")
        return None

    def get_parent_account(account_code):
        if not account_code:
            return None
        account_code_str = str(account_code)
        accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()
        for acc in accounts:
            for subaccount in acc.sub_account_details:
                if account_code_str in subaccount.get('name', ''):
                    return acc.parent_account
        return None

    def fetch_filtered_data(model, account_field, account_range):
        if hasattr(model, 'user_id'):
            data = model.query.filter(
                getattr(model, account_field).like('%-%'),
                model.user_id == current_user_id
            ).all()
        elif hasattr(model, 'created_by'):
            data = model.query.filter(
                getattr(model, account_field).like('%-%'),
                model.created_by == current_user_id
            ).all()
        else:
            data = []
            accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()
            for acc in accounts:
                for subaccount in acc.sub_account_details:
                    if 'name' in subaccount:
                        data.extend(model.query.filter(getattr(model, account_field) == subaccount['name']).all())
        filtered_data = [
            item for item in data
            if extract_account_code(getattr(item, account_field)) and
               account_range[0] <= extract_account_code(getattr(item, account_field)) <= account_range[1]
        ]
        return filtered_data

    try:
        cash_disbursements_filtered = fetch_filtered_data(CashDisbursementJournal, 'account_debited', (5000, 9999))
        cash_disbursements_data = [{
            'type': 'Cash Disbursement',
            'date': cd.disbursement_date.isoformat(),
            'reference': cd.cheque_no,
            'from': cd.to_whom_paid,
            'description': cd.description,
            'dr_amount': cd.total if cd.account_debited else 0,
            'cr_amount': cd.total if cd.account_credited else 0,
            'parent_account': get_parent_account(extract_account_code(cd.account_debited)),
            'account_name': cd.account_debited,
        } for cd in cash_disbursements_filtered if (not start_date or cd.disbursement_date >= start_date) and (not end_date or cd.disbursement_date <= end_date)]

        invoices_received_filtered = fetch_filtered_data(InvoiceReceived, 'account_debited', (5000, 9999))
        invoices_received_data = [{
            'type': 'Invoice Received',
            'date': inv.date_issued.isoformat(),
            'reference': inv.invoice_number,
            'from': inv.name,
            'description': inv.description,
            'dr_amount': inv.amount if inv.account_debited else 0,
            'cr_amount': inv.amount if inv.account_credited else 0,
            'parent_account': get_parent_account(extract_account_code(inv.account_debited)),
            'account_name': inv.account_debited,
        } for inv in invoices_received_filtered if (not start_date or inv.date_issued >= start_date) and (not end_date or inv.date_issued <= end_date)]

        transactions_filtered = (
            fetch_filtered_data(Transaction, 'debited_account_name', (5000, 9999)) +
            fetch_filtered_data(Transaction, 'credited_account_name', (5000, 9999))
        )
        transactions_data = [{
            'type': 'Transaction',
            'date': txn.date_issued.isoformat(),
            'reference': txn.id,
            'from': txn.debited_account_name,
            'description': txn.description,
            'dr_amount': txn.amount_debited,
            'cr_amount': txn.amount_credited,
            'parent_account': get_parent_account(
                extract_account_code(txn.debited_account_name) if txn.debited_account_name else
                extract_account_code(txn.credited_account_name)
            ),
            'account_name': txn.debited_account_name or txn.credited_account_name,
        } for txn in transactions_filtered if (not start_date or txn.date_issued >= start_date) and (not end_date or txn.date_issued <= end_date)]

        all_data = cash_disbursements_data + invoices_received_data + transactions_data
        total_dr = sum(item['dr_amount'] for item in all_data)
        total_cr = sum(item['cr_amount'] for item in all_data)
        closing_balance = total_dr - total_cr

        response = {
            'transactions': all_data,
            'total_dr': total_dr,
            'total_cr': total_cr,
            'closing_balance': closing_balance
        }
        return jsonify(response)

    except SQLAlchemyError as db_error:
        print(f"Database error: {db_error}")
        return jsonify({'error': 'Database error occurred while fetching expense transactions.'}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred while processing the request.'}), 500

@app.route('/liabilitytransactions', methods=['GET'])
@jwt_required()
def get_all_liabilities():
    current_user = get_jwt_identity()
    current_user_id = current_user.get('id')

    if not current_user_id:
        return jsonify({"error": "Unauthorized access. User ID not found."}), 401

    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    try:
        start_date = datetime.fromisoformat(start_date_str).date() if start_date_str else None
        end_date = datetime.fromisoformat(end_date_str).date() if end_date_str else None
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

    def extract_account_code(account_field):
        try:
            if isinstance(account_field, str) and '-' in account_field:
                return int(account_field.split('-')[0].strip())
            elif isinstance(account_field, list):
                for item in account_field:
                    if 'name' in item and '-' in item['name']:
                        return int(item['name'].split('-')[0].strip())
        except (ValueError, TypeError):
            print(f"Failed to extract account code from: {account_field}")
        return None

    def get_parent_account(account_code):
        if not account_code:
            return None
        account_code_str = str(account_code)
        accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()
        for acc in accounts:
            for subaccount in acc.sub_account_details:
                if account_code_str in subaccount.get('name', ''):
                    return acc.parent_account
        return None

    def fetch_filtered_data(model, account_field, account_range):
        if hasattr(model, 'user_id'):
            data = model.query.filter(
                getattr(model, account_field).like('%-%'),
                model.user_id == current_user_id
            ).all()
        elif hasattr(model, 'created_by'):
            data = model.query.filter(
                getattr(model, account_field).like('%-%'),
                model.created_by == current_user_id
            ).all()
        else:
            data = []
            accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()
            for acc in accounts:
                for subaccount in acc.sub_account_details:
                    if 'name' in subaccount:
                        data.extend(model.query.filter(getattr(model, account_field) == subaccount['name']).all())
        filtered_data = [
            item for item in data
            if extract_account_code(getattr(item, account_field)) and
               account_range[0] <= extract_account_code(getattr(item, account_field)) <= account_range[1]
        ]
        return filtered_data

    try:
        cash_disbursements_filtered = fetch_filtered_data(CashDisbursementJournal, 'account_debited', (2000, 2999))
        cash_disbursements_data = [{
            'id': cd.id,
            'disbursement_date': cd.disbursement_date.isoformat(),
            'cheque_no': cd.cheque_no,
            'p_voucher_no': cd.p_voucher_no,
            'to_whom_paid': cd.to_whom_paid,
            'payment_type': cd.payment_type,
            'description': cd.description,
            'account_debited': cd.account_debited,
            'parent_account': get_parent_account(extract_account_code(cd.account_debited)),
            'cashbook': cd.cashbook,
            'cash': cd.cash,
            'bank': cd.bank,
            'total': cd.total,
        } for cd in cash_disbursements_filtered if (not start_date or cd.disbursement_date >= start_date) and (not end_date or cd.disbursement_date <= end_date)]

        invoices_received_filtered = fetch_filtered_data(InvoiceReceived, 'account_debited', (2000, 2999))
        invoices_received_data = [{
            'id': inv.id,
            'invoice_number': inv.invoice_number,
            'date_issued': inv.date_issued.isoformat(),
            'description': inv.description,
            'amount': inv.amount,
            'account_debited': inv.account_debited,
            'parent_account': get_parent_account(extract_account_code(inv.account_debited)),
            'name': inv.name
        } for inv in invoices_received_filtered if (not start_date or inv.date_issued >= start_date) and (not end_date or inv.date_issued <= end_date)]

        transactions_filtered = (
            fetch_filtered_data(Transaction, 'debited_account_name', (2000, 2999)) +
            fetch_filtered_data(Transaction, 'credited_account_name', (2000, 2999))
        )
        transactions_data = [{
            'id': txn.id,
            'debited_account_name': txn.debited_account_name,
            'credited_account_name': txn.credited_account_name,
            'amount_debited': txn.amount_debited,
            'amount_credited': txn.amount_credited,
            'description': txn.description,
            'date_issued': txn.date_issued.isoformat(),
            'parent_account': get_parent_account(
                extract_account_code(txn.debited_account_name) if txn.debited_account_name else
                extract_account_code(txn.credited_account_name)
            ),
        } for txn in transactions_filtered if (not start_date or txn.date_issued >= start_date) and (not end_date or txn.date_issued <= end_date)]

        response = {
            'cash_disbursements': cash_disbursements_data,
            'invoices_received': invoices_received_data,
            'transactions': transactions_data
        }
        return jsonify(response)

    except SQLAlchemyError as db_error:
        print(f"Database error: {db_error}")
        return jsonify({'error': 'Database error occurred while fetching liability transactions.'}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred while processing the request.'}), 500


@app.route('/net-assets', methods=['GET'])
@jwt_required()
def get_net_assets():
    current_user = get_jwt_identity()
    current_user_id = current_user.get('id')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    try:
        start_date = datetime.fromisoformat(start_date_str).date() if start_date_str else None
        end_date = datetime.fromisoformat(end_date_str).date() if end_date_str else None
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

    def extract_account_code(account_field):
        if isinstance(account_field, list):
            for item in account_field:
                if 'name' in item:
                    account_name = item['name']
                    if account_name and '-' in account_name:
                        try:
                            return int(account_name.split('-')[0].strip())
                        except ValueError:
                            print(f"Failed to extract account code from: {account_name}")
                            continue
            print(f"Invalid account field format: {account_field}")
            return None
        elif isinstance(account_field, str):
            if account_field and '-' in account_field:
                try:
                    return int(account_field.split('-')[0].strip())
                except ValueError:
                    print(f"Failed to extract account code from: {account_field}")
                    return None
            print(f"Invalid account field format: {account_field}")
            return None
        else:
            print(f"Invalid account field format: {account_field}")
            return None

    def get_parent_account(account_code, accounts):
        if account_code:
            account_code_str = str(account_code)
            for acc in accounts:
                for subaccount in acc.sub_account_details:
                    if account_code_str in subaccount.get('name', ''):
                        return acc.parent_account
            return ''
        return ''

    def is_account_in_range(account):
        if account and account.split('-')[0].strip().isdigit():
            account_number = int(account.split('-')[0].strip())
            return 3000 <= account_number <= 3999
        return False

    try:
        transactions = Transaction.query.filter_by(user_id=current_user_id).all()
        accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()
        total_credits = 0.0
        total_debits = 0.0
        filtered_transactions = []
        for txn in transactions:
            credited_account = txn.credited_account_name
            debited_account = txn.debited_account_name
            credited_in_range = is_account_in_range(credited_account)
            debited_in_range = is_account_in_range(debited_account)
            if credited_in_range or debited_in_range:
                txn_date = txn.date_issued.date() if isinstance(txn.date_issued, datetime) else txn.date_issued
                if (not start_date or txn_date >= start_date) and (not end_date or txn_date <= end_date):
                    filtered_transactions.append(txn)
                    if credited_in_range:
                        total_credits += txn.amount_credited
                    if debited_in_range:
                        total_debits += txn.amount_debited

        net_assets = total_credits - total_debits
        response = {
            'total_credits': round(total_credits, 2),
            'total_debits': round(total_debits, 2),
            'net_assets': round(net_assets, 2),
            'transactions': [
                {
                    'id': txn.id,
                    'credited_account_name': txn.credited_account_name,
                    'debited_account_name': txn.debited_account_name,
                    'amount_credited': round(txn.amount_credited, 2) if is_account_in_range(txn.credited_account_name) else 0.0,
                    'amount_debited': round(txn.amount_debited, 2) if is_account_in_range(txn.debited_account_name) else 0.0,
                    'description': txn.description,
                    'date_issued': txn.date_issued.isoformat() if txn.date_issued else None,
                    'parent_account_credited': get_parent_account(extract_account_code(txn.credited_account_name), accounts),
                    'parent_account_debited': get_parent_account(extract_account_code(txn.debited_account_name), accounts),
                }
                for txn in filtered_transactions
            ]
        }
        return jsonify(response), 200
    except Exception as e:
        print(f"Error fetching net assets: {str(e)}")
        return jsonify({'error': str(e)}), 500



@app.route('/assettransactions', methods=['GET'])
@jwt_required()
def get_all_assets():
    current_user = get_jwt_identity()
    current_user_id = current_user.get('id')

    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    try:
        start_date = datetime.fromisoformat(start_date_str).date() if start_date_str else None
        end_date = datetime.fromisoformat(end_date_str).date() if end_date_str else None
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

    def extract_account_code(account_field):
        if isinstance(account_field, list):
            for item in account_field:
                if 'name' in item:
                    account_name = item['name']
                    if account_name and '-' in account_name:
                        try:
                            return int(account_name.split('-')[0].strip())
                        except ValueError:
                            print(f"Failed to extract account code from: {account_name}")
                            continue
            print(f"Invalid account field format: {account_field}")
            return None
        elif isinstance(account_field, str) and '-' in account_field:
            try:
                return int(account_field.split('-')[0].strip())
            except ValueError:
                print(f"Failed to extract account code from: {account_field}")
                return None
        return None

    def get_parent_account(account_code):
        if account_code:
            account_code_str = str(account_code)
            accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()
            for acc in accounts:
                for subaccount in acc.sub_account_details:
                    if account_code_str in subaccount.get('name', ''):
                        return acc.parent_account
            return ''
        return ''

    def fetch_filtered_data(model, account_field, account_range):
        if hasattr(model, 'user_id'):
            data = model.query.filter(
                getattr(model, account_field).like('%-%'),
                model.user_id == current_user_id
            ).all()
        elif hasattr(model, 'created_by'):
            data = model.query.filter(
                getattr(model, account_field).like('%-%'),
                model.created_by == current_user_id
            ).all()
        else:
            data = []
            accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()
            for acc in accounts:
                for subaccount in acc.sub_account_details:
                    if 'name' in subaccount:
                        data.extend(model.query.filter(getattr(model, account_field) == subaccount['name']).all())
        filtered_data = [
            item for item in data
            if extract_account_code(getattr(item, account_field)) and account_range[0] <= extract_account_code(getattr(item, account_field)) <= account_range[1]
        ]
        return filtered_data

    try:
        cash_disbursements_filtered = fetch_filtered_data(CashDisbursementJournal, 'account_debited', (1100, 1999))
        cash_disbursements_data = [{
            'id': cd.id,
            'disbursement_date': cd.disbursement_date.isoformat(),
            'cheque_no': cd.cheque_no,
            'p_voucher_no': cd.p_voucher_no,
            'to_whom_paid': cd.to_whom_paid,
            'payment_type': cd.payment_type,
            'description': cd.description,
            'account_debited': cd.account_debited,
            'account_credited': cd.account_credited,
            'parent_account': get_parent_account(extract_account_code(cd.account_debited)),
            'cashbook': cd.cashbook,
            'cash': cd.cash,
            'bank': cd.bank,
            'total': cd.total,
            'created_by': cd.created_by,
        } for cd in cash_disbursements_filtered if (not start_date or cd.disbursement_date >= start_date) and (not end_date or cd.disbursement_date <= end_date)]

        invoices_received_filtered = fetch_filtered_data(InvoiceReceived, 'account_debited', (1100, 1999)) + fetch_filtered_data(InvoiceReceived, 'account_credited', (1100, 1999))
        invoices_received_data = [{
            'id': inv.id,
            'invoice_number': inv.invoice_number,
            'date_issued': inv.date_issued.isoformat(),
            'description': inv.description,
            'amount': inv.amount,
            'user_id': inv.user_id,
            'account_debited': inv.account_debited,
            'account_credited': inv.account_credited,
            'parent_account': get_parent_account(extract_account_code(inv.account_debited)),
            'name': inv.name
        } for inv in invoices_received_filtered if (not start_date or inv.date_issued >= start_date) and (not end_date or inv.date_issued <= end_date)]

        invoices_issued_filtered = fetch_filtered_data(InvoiceIssued, 'account_debited', (1100, 1999)) + fetch_filtered_data(InvoiceIssued, 'account_credited', (1100, 1999))
        invoices_issued_data = [{
            'id': inv.id,
            'invoice_number': inv.invoice_number,
            'date_issued': inv.date_issued.isoformat(),
            'description': inv.description,
            'amount': inv.amount,
            'user_id': inv.user_id,
            'account_debited': inv.account_debited,
            'account_credited': inv.account_credited,
            'parent_account': get_parent_account(
                extract_account_code(inv.account_debited) if extract_account_code(inv.account_debited) and 1100 <= extract_account_code(inv.account_debited) <= 1999
                else extract_account_code(inv.account_credited)
            ),
            'name': inv.name
        } for inv in invoices_issued_filtered if (not start_date or inv.date_issued >= start_date) and (not end_date or inv.date_issued <= end_date)]

        cash_receipts_filtered = fetch_filtered_data(CashReceiptJournal, 'account_credited', (1100, 1999))
        cash_receipts_data = [{
            'id': cr.id,
            'receipt_date': cr.receipt_date.isoformat(),
            'receipt_no': cr.receipt_no,
            'ref_no': cr.ref_no,
            'from_whom_received': cr.from_whom_received,
            'description': cr.description,
            'receipt_type': cr.receipt_type,
            'account_credited': cr.account_credited,
            'account_debited': cr.account_debited,
            'bank': cr.bank,
            'cash': cr.cash,
            'total': cr.total,
            'cashbook': cr.cashbook,
            'created_by': cr.created_by,
            'name': cr.name,
            'parent_account': get_parent_account(extract_account_code(cr.account_credited)),
        } for cr in cash_receipts_filtered if (not start_date or cr.receipt_date >= start_date) and (not end_date or cr.receipt_date <= end_date)]

        transactions_filtered = fetch_filtered_data(Transaction, 'debited_account_name', (1100, 1999)) + fetch_filtered_data(Transaction, 'credited_account_name', (1100, 1999))
        transactions_data = [{
            'id': txn.id,
            'debited_account_name': txn.debited_account_name,
            'credited_account_name': txn.credited_account_name,
            'amount_debited': txn.amount_debited,
            'amount_credited': txn.amount_credited,
            'description': txn.description,
            'date_issued': txn.date_issued.isoformat(),
            'parent_account': get_parent_account(
                extract_account_code(txn.debited_account_name) if extract_account_code(txn.debited_account_name) and 1100 <= extract_account_code(txn.debited_account_name) <= 1999
                else extract_account_code(txn.credited_account_name)
            ),
        } for txn in transactions_filtered if (not start_date or txn.date_issued >= start_date) and (not end_date or txn.date_issued <= end_date)]

        response = {
            'cash_disbursements': cash_disbursements_data,
            'invoices_received': invoices_received_data,
            'invoices_issued': invoices_issued_data,
            'cash_receipts': cash_receipts_data,
            'transactions': transactions_data
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    



@app.route('/revenuetransactions', methods=['GET'])
@jwt_required()
def get_all_revenue():
    current_user = get_jwt_identity()
    current_user_id = current_user.get('id')

    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    try:
        start_date = datetime.fromisoformat(start_date_str).date() if start_date_str else None
        end_date = datetime.fromisoformat(end_date_str).date() if end_date_str else None
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD."}), 400

    def extract_account_code(account_field):
        if isinstance(account_field, list):
            for item in account_field:
                if 'name' in item:
                    account_name = item['name']
                    if account_name and '-' in account_name:
                        try:
                            return int(account_name.split('-')[0].strip())
                        except ValueError:
                            print(f"Failed to extract account code from: {account_name}")
                            continue
            print(f"Invalid account field format: {account_field}")
            return None
        elif isinstance(account_field, str):
            if account_field and '-' in account_field:
                try:
                    return int(account_field.split('-')[0].strip())
                except ValueError:
                    print(f"Failed to extract account code from: {account_field}")
                    return None
            print(f"Invalid account field format: {account_field}")
            return None
        else:
            print(f"Unsupported account field type: {type(account_field)}")
            return None

    def get_parent_account(account_code):
        if account_code:
            account_code_str = str(account_code)
            accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()
            for acc in accounts:
                for subaccount in acc.sub_account_details:
                    if account_code_str in subaccount.get('name', ''):
                        return acc.parent_account
            return None
        return None

    def fetch_filtered_data(model, account_field, account_range):
        if hasattr(model, 'user_id'):
            data = model.query.filter(
                getattr(model, account_field).like('%-%'),
                model.user_id == current_user_id
            ).all()
        elif hasattr(model, 'created_by'):
            data = model.query.filter(
                getattr(model, account_field).like('%-%'),
                model.created_by == current_user_id
            ).all()
        else:
            data = []
            accounts = ChartOfAccounts.query.filter_by(user_id=current_user_id).all()
            for acc in accounts:
                for subaccount in acc.sub_account_details:
                    if 'name' in subaccount:
                        data.extend(model.query.filter(getattr(model, account_field) == subaccount['name']).all())
        filtered_data = [
            item for item in data
            if extract_account_code(getattr(item, account_field)) is not None
            and account_range[0] <= extract_account_code(getattr(item, account_field)) <= account_range[1]
        ]
        return filtered_data

    try:
        cash_receipts_filtered = fetch_filtered_data(CashReceiptJournal, 'account_credited', (4000, 4999))
        cash_receipts_data = [{
            'id': cr.id,
            'receipt_date': cr.receipt_date.isoformat(),
            'receipt_no': cr.receipt_no,
            'ref_no': cr.ref_no,
            'from_whom_received': cr.from_whom_received,
            'description': cr.description,
            'receipt_type': cr.receipt_type,
            'account_credited': cr.account_credited,
            'parent_account': get_parent_account(extract_account_code(cr.account_credited)),
            'bank': cr.bank,
            'cash': cr.cash,
            'total': cr.total,
            'cashbook': cr.cashbook,
            'created_by': cr.created_by,
            'name': cr.name
        } for cr in cash_receipts_filtered if (not start_date or cr.receipt_date >= start_date) and (not end_date or cr.receipt_date <= end_date)]

        invoices_issued_filtered = fetch_filtered_data(InvoiceIssued, 'account_credited', (4000, 4999))
        invoices_issued_data = [{
            'id': inv.id,
            'invoice_number': inv.invoice_number,
            'date_issued': inv.date_issued.isoformat(),
            'description': inv.description,
            'amount': inv.amount,
            'user_id': inv.user_id,
            'account_credited': inv.account_credited,
            'parent_account': get_parent_account(extract_account_code(inv.account_credited)),
            'name': inv.name
        } for inv in invoices_issued_filtered if (not start_date or inv.date_issued >= start_date) and (not end_date or inv.date_issued <= end_date)]

        transactions_filtered = fetch_filtered_data(Transaction, 'debited_account_name', (4000, 4999)) + fetch_filtered_data(Transaction, 'credited_account_name', (4000, 4999))
        transactions_data = [{
            'id': txn.id,
            'debited_account_name': txn.debited_account_name,
            'amount_debited': txn.amount_debited,
            'description': txn.description,
            'date_issued': txn.date_issued.isoformat(),
            'parent_account': get_parent_account(extract_account_code(txn.debited_account_name) if txn.debited_account_name else extract_account_code(txn.credited_account_name)),
        } for txn in transactions_filtered if (not start_date or txn.date_issued >= start_date) and (not end_date or txn.date_issued <= end_date)]

        response = {
            'cash_receipts': cash_receipts_data,
            'invoices_issued': invoices_issued_data,
            'transactions': transactions_data
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    
    


# Initialize trial balance dictionary
trial_balance = {}

def update_trial_balance(account, debit, credit):
    # Ensure the account is a string (hashable)
    if not isinstance(account, str):
        account = str(account)  # Convert to string if necessary

    if account not in trial_balance:
        trial_balance[account] = {'debit': 0, 'credit': 0}
    trial_balance[account]['debit'] += debit
    trial_balance[account]['credit'] += credit

@app.route('/trial-balance', methods=['GET'])
def get_trial_balance():
    global trial_balance
    trial_balance = {}  # Reset trial balance for each request

    try:
        # Debug: Print data from each table
        print("Transactions:")
        transactions = db.session.query(
            Transaction.debited_account_name,
            func.sum(Transaction.amount_debited).label('total_debit'),
            Transaction.credited_account_name,
            func.sum(Transaction.amount_credited).label('total_credit')
        ).group_by(Transaction.debited_account_name, Transaction.credited_account_name).all()
        print(transactions)

        for transaction in transactions:
            update_trial_balance(transaction.debited_account_name, transaction.total_debit, 0)
            update_trial_balance(transaction.credited_account_name, 0, transaction.total_credit)

        print("Invoice Issued:")
        invoices_issued = db.session.query(
            InvoiceIssued.account_debited,
            InvoiceIssued.account_credited  # Fetch the credited accounts as a JSON field
        ).all()
        print(invoices_issued)

        for invoice in invoices_issued:
            credited_accounts = invoice.account_credited
            if not isinstance(credited_accounts, list):
                credited_accounts = []

            total_credit = sum(account['amount'] for account in credited_accounts)
            update_trial_balance(invoice.account_debited, total_credit, 0)

            for account in credited_accounts:
                update_trial_balance(account['name'], 0, account['amount'])

        print("Invoice Received:")
        invoices_received = db.session.query(
            InvoiceReceived.account_debited,
            func.sum(InvoiceReceived.amount).label('total_debit'),
            InvoiceReceived.account_credited
        ).group_by(InvoiceReceived.account_debited, InvoiceReceived.account_credited).all()
        print(invoices_received)

        for invoice in invoices_received:
            total_debit = invoice.total_debit
            update_trial_balance(invoice.account_debited, total_debit, 0)
            if invoice.account_credited:
                update_trial_balance(invoice.account_credited, 0, total_debit)

        print("Cash Receipts:")
        cash_receipts = db.session.query(
            CashReceiptJournal.account_debited,
            func.sum(CashReceiptJournal.total).label('total_debit'),
            CashReceiptJournal.account_credited
        ).group_by(CashReceiptJournal.account_debited, CashReceiptJournal.account_credited).all()
        print(cash_receipts)

        for receipt in cash_receipts:
            update_trial_balance(receipt.account_debited, receipt.total_debit, 0)
            if receipt.account_credited:
                update_trial_balance(receipt.account_credited, 0, receipt.total_debit)

        print("Cash Disbursements:")
        cash_disbursements = db.session.query(
            CashDisbursementJournal.account_debited,
            func.sum(CashDisbursementJournal.total).label('total_debit'),
            CashDisbursementJournal.account_credited
        ).group_by(CashDisbursementJournal.account_debited, CashDisbursementJournal.account_credited).all()
        print(cash_disbursements)

        for disbursement in cash_disbursements:
            update_trial_balance(disbursement.account_debited, disbursement.total_debit, 0)
            if disbursement.account_credited:
                update_trial_balance(disbursement.account_credited, 0, disbursement.total_debit)

        # Prepare the final trial balance
        final_trial_balance = []
        for account, balances in trial_balance.items():
            final_trial_balance.append({
                'account': account,
                'debit': balances['debit'],
                'credit': balances['credit'],
                'balance': balances['debit'] - balances['credit']
            })

        return jsonify({
            'status': 'success',
            'trial_balance': final_trial_balance
        }), 200

    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500




@app.route('/income-statement/accounts', methods=['GET'])
@jwt_required()
def get_income_accounts_debited_credited():
    current_user = get_jwt_identity()
    current_user_id = current_user.get('id')

    # Query all transactions from each model
    invoices_issued = db.session.query(InvoiceIssued).all()
    invoices_received = db.session.query(InvoiceReceived).all()
    cash_receipts = db.session.query(CashReceiptJournal).all()
    cash_disbursements = db.session.query(CashDisbursementJournal).all()
    transactions = db.session.query(Transaction).all()  # Include the Transaction model

    # Debugging: Check the number of transactions fetched
    print(f"Invoices Issued: {len(invoices_issued)}")
    print(f"Invoices Received: {len(invoices_received)}")
    print(f"Cash Receipts: {len(cash_receipts)}")
    print(f"Cash Disbursements: {len(cash_disbursements)}")
    print(f"Transactions: {len(transactions)}")

    # Retrieve all accounts once to optimize performance
    all_accounts = ChartOfAccounts.query.all()

    # Function to get parent account details and account names based on account code
    def get_parent_account_details(account_code):
        """Get the parent account details and account names based on account code."""
        if isinstance(account_code, dict):  # Handle JSON object
            account_code = account_code.get('name', '')
        elif isinstance(account_code, list):  # Handle JSON array
            account_code = account_code[0].get('name', '') if account_code else ''

        if account_code:
            account_code_str = str(account_code)
            for acc in all_accounts:
                for subaccount in acc.sub_account_details:
                    if account_code_str in subaccount.get('name', ''):
                        return {
                            "parent_account": acc.parent_account,
                            "account_name": acc.account_name,
                            "account_type": acc.account_type,
                            "note_number": acc.note_number,
                            "sub_account_name": subaccount.get('name', '')
                        }
        return {}  # Return empty dictionary if no parent account is found

    # Combine all transactions into a single list
    all_transactions = (
        invoices_issued + invoices_received + cash_receipts + cash_disbursements + transactions
    )

    # Initialize account_groups with all accounts in the range 400-599
    account_groups = defaultdict(lambda: {
        "parent_accounts": {},  # Store parent accounts and their individual amounts and notes
        "relevant_accounts": set(),  # Store relevant sub-accounts
        "total_amount": 0.0,  # Total amount for the account group
        "account_type": None  # Add account type to the group
    })

    # Fetch all accounts in the range 400-599 and initialize them
    for acc in all_accounts:
        if acc.account_name and acc.account_name.split('-')[0].isdigit():
            account_number = int(acc.account_name.split('-')[0])
            if 400 <= account_number <= 599:
                # Initialize the account group if it doesn't exist
                if acc.account_name not in account_groups:
                    account_groups[acc.account_name] = {
                        "parent_accounts": {},
                        "relevant_accounts": set(),
                        "total_amount": 0.0,
                        "account_type": acc.account_type  # Include account type here
                    }
                # Initialize parent accounts for the account group
                for subaccount in acc.sub_account_details:
                    parent_account = subaccount.get('name', '')
                    if parent_account:
                        account_groups[acc.account_name]["parent_accounts"][parent_account] = {
                            "amount": 0.0,
                            "note_number": acc.note_number  # Include note number for the parent account
                        }

    # Process transactions and update amounts for accounts with transactions
    for transaction in all_transactions:
        # Initialize variables for amount, debited_account, and credited_account
        amount = 0.0
        debited_account = None
        credited_account = None

        # Process different transaction types
        if isinstance(transaction, InvoiceIssued):
            amount = transaction.amount
            debited_account = transaction.account_debited
            credited_account = transaction.account_credited
        elif isinstance(transaction, InvoiceReceived):
            amount = transaction.amount
            debited_account = transaction.account_debited
            credited_account = transaction.account_credited
        elif isinstance(transaction, CashReceiptJournal):
            amount = transaction.total
            debited_account = transaction.account_debited
            credited_account = transaction.account_credited
        elif isinstance(transaction, CashDisbursementJournal):
            amount = transaction.total
            debited_account = transaction.account_debited
            credited_account = transaction.account_credited
        elif isinstance(transaction, Transaction):
            amount = transaction.amount_debited
            debited_account = transaction.debited_account_name
            credited_account = transaction.credited_account_name
        else:
            continue  # Skip any unsupported transaction type

        # Round amount to two decimal places to avoid floating-point issues
        amount = round(amount, 2)

        # Get parent account details for debited and credited accounts
        parent_debited = get_parent_account_details(debited_account)
        parent_credited = get_parent_account_details(credited_account)

        # Debugging: Check the transaction details
        print(f"Transaction: {transaction}")
        print(f"Amount: {amount}")
        print(f"Debited Account: {debited_account}, Parent: {parent_debited}")
        print(f"Credited Account: {credited_account}, Parent: {parent_credited}")

        # Function to check if the account name is within the range 400-599
        def is_account_in_range(account_name):
            """Check if the account name starts with a number between 400 and 599."""
            if account_name and account_name.split('-')[0].isdigit():
                account_number = int(account_name.split('-')[0])
                return 400 <= account_number <= 599
            return False

        # Handle debited account information
        if parent_debited and parent_debited.get("account_name"):
            account_name = parent_debited.get("account_name")
            if is_account_in_range(account_name):  # Only process if account is in range 400-599
                parent_account = parent_debited.get("parent_account")
                sub_account_name = parent_debited.get("sub_account_name")
                note_number = parent_debited.get("note_number")
                # Initialize parent account amount if it doesn't exist
                if parent_account not in account_groups[account_name]["parent_accounts"]:
                    account_groups[account_name]["parent_accounts"][parent_account] = {
                        "amount": 0.0,
                        "note_number": note_number
                    }
                # Add amount to the parent account
                account_groups[account_name]["parent_accounts"][parent_account]["amount"] += amount
                account_groups[account_name]["relevant_accounts"].add(sub_account_name)
                account_groups[account_name]["total_amount"] += amount

        # Handle credited account information
        if parent_credited and parent_credited.get("account_name"):
            account_name = parent_credited.get("account_name")
            if is_account_in_range(account_name):  # Only process if account is in range 400-599
                parent_account = parent_credited.get("parent_account")
                sub_account_name = parent_credited.get("sub_account_name")
                note_number = parent_credited.get("note_number")
                # Initialize parent account amount if it doesn't exist
                if parent_account not in account_groups[account_name]["parent_accounts"]:
                    account_groups[account_name]["parent_accounts"][parent_account] = {
                        "amount": 0.0,
                        "note_number": note_number
                    }
                # Add amount to the parent account
                account_groups[account_name]["parent_accounts"][parent_account]["amount"] += amount
                account_groups[account_name]["relevant_accounts"].add(sub_account_name)
                account_groups[account_name]["total_amount"] += amount

        # Handle credited account information for InvoiceIssued where credited_account is a list
        if isinstance(transaction, InvoiceIssued) and isinstance(credited_account, list):
            for credit in credited_account:
                credit_name = credit.get('name')
                credit_amount = credit.get('amount', 0.0)
                parent_credited = get_parent_account_details(credit_name)
                if parent_credited and parent_credited.get("account_name"):
                    account_name = parent_credited.get("account_name")
                    if is_account_in_range(account_name):  # Only process if account is in range 400-599
                        parent_account = parent_credited.get("parent_account")
                        sub_account_name = parent_credited.get("sub_account_name")
                        note_number = parent_credited.get("note_number")
                        # Initialize parent account amount if it doesn't exist
                        if parent_account not in account_groups[account_name]["parent_accounts"]:
                            account_groups[account_name]["parent_accounts"][parent_account] = {
                                "amount": 0.0,
                                "note_number": note_number
                            }
                        # Add amount to the parent account
                        account_groups[account_name]["parent_accounts"][parent_account]["amount"] += credit_amount
                        account_groups[account_name]["relevant_accounts"].add(sub_account_name)
                        account_groups[account_name]["total_amount"] += credit_amount

    # Convert defaultdict to a regular dictionary for JSON serialization
    account_groups = {
        account_name: {
            "parent_accounts": {
                parent_account: {
                    "amount": data["amount"],
                    "note_number": data["note_number"]
                }
                for parent_account, data in account_data["parent_accounts"].items()
            },
            "relevant_accounts": list(account_data["relevant_accounts"]),
            "total_amount": round(account_data["total_amount"], 2),
            "account_type": account_data["account_type"]  # Include account type in the response
        }
        for account_name, account_data in account_groups.items()
    }

    # Debugging: Check the final account groups
    print(f"Account Groups: {account_groups}")
    return jsonify(account_groups)





@app.route('/balance-statement/accounts', methods=['GET'])
@jwt_required()
def get_balance_accounts_debited_credited():
    try:
        # Get current user identity
        current_user = get_jwt_identity()
        current_user_id = current_user.get('id')

        # Query all transactions
        invoices_issued = db.session.query(InvoiceIssued).filter_by(user_id=current_user_id).all()
        invoices_received = db.session.query(InvoiceReceived).filter_by(user_id=current_user_id).all()
        cash_receipts = db.session.query(CashReceiptJournal).filter_by(created_by=current_user_id).all()
        cash_disbursements = db.session.query(CashDisbursementJournal).filter_by(created_by=current_user_id).all()
        transactions = db.session.query(Transaction).all()

        # Debugging: Check the number of transactions fetched
        logging.debug(f"Invoices Issued: {len(invoices_issued)}")
        logging.debug(f"Invoices Received: {len(invoices_received)}")
        logging.debug(f"Cash Receipts: {len(cash_receipts)}")
        logging.debug(f"Cash Disbursements: {len(cash_disbursements)}")
        logging.debug(f"Transactions: {len(transactions)}")

        # Retrieve all accounts once to optimize performance
        all_accounts = ChartOfAccounts.query.all()

        # Initialize account_groups with all accounts and sub-accounts
        account_groups = defaultdict(lambda: {
            "parent_account": None,  # Parent account name
            "note_number": None,     # Note number from ChartOfAccounts
            "total_amount": 0.0,     # Total amount for the account
            "account_type": None,    # Account type (e.g., Assets, Liabilities)
            "account_name": None     # Account name (e.g., 1005- Operations Acc)
        })
        def is_account_in_range(account_name):
                    try:
                        account_number = int(account_name.split('-')[0].strip())
                        return 100 <= account_number <= 399
                    except (ValueError, IndexError):
                        return False
        # Populate account_groups with parent accounts and sub-accounts
        for acc in all_accounts:
            if acc.account_name and acc.account_name.split('-')[0].isdigit():
                account_name = acc.account_name.strip()  # Normalize account name
                account_groups[account_name] = {
                    "parent_account": acc.parent_account,  # Parent account name
                    "note_number": acc.note_number,        # Note number
                    "total_amount": 0.0,                   # Initialize total amount
                    "account_type": acc.account_type,       # Account type
                    "account_name": acc.account_name        # Account name
                }
                
                # Add sub-accounts to account_groups
                for subaccount in acc.sub_account_details:
                    subaccount_name = subaccount.get('name', '').strip()  # Normalize subaccount name
                    if subaccount_name:
                        account_groups[subaccount_name] = {
                            "parent_account": acc.parent_account,  # Parent account name
                            "note_number": acc.note_number,        # Note number
                            "total_amount": 0.0,                   # Initialize total amount
                            "account_type": acc.account_type,       # Account type
                            "account_name": account_name       # Sub-account name
                        }

        # Log all account names in account_groups
        logging.debug(f"Account Groups Keys: {list(account_groups.keys())}")

        # Function to update trial balance
        def update_trial_balance(account_name, debit_amount, credit_amount):
            """Update the trial balance for a given account."""
            if isinstance(account_name, (str, dict, list)):
                # Normalize account name
                if isinstance(account_name, dict):
                    account_name = account_name.get('name', '')
                elif isinstance(account_name, list):
                    account_name = account_name[0].get('name', '') if account_name else ''
                
                # Trim whitespace and normalize case
                account_name = account_name.strip()

                # Check if the account exists in account_groups
                if account_name in account_groups:
                    account_groups[account_name]["total_amount"] += (debit_amount - credit_amount)
                else:
                    logging.error(f"Account name not found: {account_name}")
            else:
                logging.error(f"Invalid account name type: {account_name} (type: {type(account_name)})")

        # Process transactions and update amounts for accounts with transactions
        for transaction in transactions:
            debited_account_name = transaction.debited_account_name
            credited_account_name = transaction.credited_account_name
            update_trial_balance(debited_account_name, transaction.amount_debited or 0, 0)
            update_trial_balance(credited_account_name, 0, transaction.amount_credited or 0)

        # Process invoices issued
        for invoice in invoices_issued:
            debited_account_name = invoice.account_debited
            credited_accounts = invoice.account_credited
            if isinstance(credited_accounts, list):
                for credited_account in credited_accounts:
                    credited_account_name = credited_account.get('name', '')
                    credited_amount = credited_account.get('amount', 0)
                    update_trial_balance(debited_account_name, credited_amount, 0)
                    update_trial_balance(credited_account_name, 0, credited_amount)

        # Process invoices received
        for invoice in invoices_received:
            debited_accounts = invoice.account_debited
            credited_account_name = invoice.account_credited
            if isinstance(debited_accounts, list):
                for debited_account in debited_accounts:
                    debited_account_name = debited_account.get('name', '')
                    debited_amount = debited_account.get('amount', 0)
                    update_trial_balance(debited_account_name, debited_amount, 0)
                    update_trial_balance(credited_account_name, 0, debited_amount)

        # Process cash receipts
        for receipt in cash_receipts:
            debited_account_name = receipt.account_debited
            credited_account_name = receipt.account_credited
            total_amount = receipt.total or 0
            update_trial_balance(debited_account_name, total_amount, 0)
            update_trial_balance(credited_account_name, 0, total_amount)

        # Process cash disbursements
        for disbursement in cash_disbursements:
            debited_account_name = disbursement.account_debited
            credited_account_name = disbursement.account_credited
            total_amount = disbursement.total or 0
            update_trial_balance(debited_account_name, total_amount, 0)
            update_trial_balance(credited_account_name, 0, total_amount)

        # Convert defaultdict to a regular dictionary for JSON serialization
        account_groups = {
            account_name: {
                "parent_account": account_data["parent_account"],  # Parent account name
                "note_number": account_data["note_number"],         # Note number
                "total_amount": round(account_data["total_amount"], 2),  # Total amount
                "account_type": account_data["account_type"],       # Account type
                "account_name": account_data["account_name"]        # Account name
            }
            for account_name, account_data in account_groups.items()
        }

        # Debugging: Check the final account groups
        logging.debug(f"Account Groups: {account_groups}")
        return jsonify(account_groups)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500



import logging
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/transactions/accounts', methods=['GET'])
def get_accounts():
    # Query all transactions from each model
    invoices_issued = InvoiceIssued.query.all()
    invoices_received = InvoiceReceived.query.all()
    cash_receipts = CashReceiptJournal.query.all()
    cash_disbursements = CashDisbursementJournal.query.all()
    transactions = Transaction.query.all()

    # Retrieve all accounts once to optimize performance
    accounts = ChartOfAccounts.query.all()

    # Helper function to get parent account details based on account code
    def get_parent_account_details(account_code):
        """Get the parent account details based on account code."""
        if account_code:
            account_code_str = str(account_code)
            for acc in accounts:
                for subaccount in acc.sub_account_details or []:
                    if account_code_str in subaccount.get('name', ''):
                        return {
                            "parent_account": acc.parent_account,
                            "account_name": acc.account_name,
                            "account_type": acc.account_type,
                            "note_number": acc.note_number,
                        }
        return {}

    # Initialize a dictionary to track account balances
    account_balances = defaultdict(lambda: {"debit": 0.0, "credit": 0.0, "parent_account": None, "note_number": None})

    # Combine all transactions into a single list
    all_transactions = (
        invoices_issued + invoices_received + cash_receipts + cash_disbursements + transactions
    )

    for transaction in all_transactions:
        amount, debited_account, credited_accounts = extract_transaction_details(transaction)

        # Log raw credited_accounts for debugging
        logging.info(f"Processing transaction ID {getattr(transaction, 'id', 'N/A')}: "
                     f"credited_accounts = {credited_accounts}")

        # Mirror amounts to ensure balance
        total_debited_amount, total_credited_amount = mirror_amounts(amount, debited_account, credited_accounts)

        # Update account balances for the debited account
        if debited_account:
            update_account_balances(debited_account, total_debited_amount, 0, account_balances)

        # Update account balances for credited accounts
        if credited_accounts:
            for credited_account in credited_accounts:
                if isinstance(credited_account, dict) and 'name' in credited_account and 'amount' in credited_account:
                    update_account_balances(credited_account['name'], 0, credited_account['amount'], account_balances)
                else:
                    logging.warning(f"Invalid credited_account structure: {credited_account} "
                                    f"in transaction ID {getattr(transaction, 'id', 'N/A')}")

    # Prepare the final account balances
    final_account_balances = []
    parent_account_balances = defaultdict(lambda: {"debit": 0.0, "credit": 0.0})

    for account, balances in account_balances.items():
        parent_account_details = get_parent_account_details(account)
        parent_account = parent_account_details.get('parent_account')

        # Calculate the balance if it's not already present
        if 'balance' not in balances:
            balances['balance'] = round(balances['debit'] - balances['credit'], 2)

        # Add the account's balance to its parent account's total
        if parent_account:
            parent_account_balances[parent_account]["debit"] += balances['debit']
            parent_account_balances[parent_account]["credit"] += balances['credit']

        # Append the individual account balance to the final list
        final_account_balances.append({
            'account': account,
            'debit': round(balances['debit'], 2),
            'credit': round(balances['credit'], 2),
            'balance': balances['balance'],
            'parent_account': parent_account,
            'note_number': parent_account_details.get('note_number')
        })

    # Add parent account balances to the final list
    for parent_account, balances in parent_account_balances.items():
        parent_balance = round(balances['debit'] - balances['credit'], 2)

        final_account_balances.append({
            'account': parent_account,
            'debit': round(balances['debit'], 2),
            'credit': round(balances['credit'], 2),
            'balance': parent_balance,
            'parent_account': None,  # Parent accounts do not have a parent
            'note_number': None      # Note number is optional for parent accounts
        })

    return jsonify({
        'status': 'success',
        'account_balances': final_account_balances
    }), 200
# ===================== HELPER FUNCTIONS =====================

def extract_transaction_details(transaction):
    """Extract transaction details (amount, debited account, credited accounts) based on type."""
    amount = 0
    debited_account = None
    credited_accounts = []

    if isinstance(transaction, InvoiceIssued):
        amount = transaction.amount
        debited_account = transaction.account_debited
        credited_accounts = transaction.account_credited or []
    elif isinstance(transaction, InvoiceReceived):
        amount = transaction.amount
        debited_account = transaction.account_debited or []
        credited_accounts = transaction.account_credited or []
    elif isinstance(transaction, CashReceiptJournal):
        amount = transaction.total
        debited_account = transaction.account_debited
        credited_accounts = transaction.account_credited or []
    elif isinstance(transaction, CashDisbursementJournal):
        amount = transaction.total
        debited_account = transaction.account_debited
        credited_accounts = transaction.account_credited or []
    elif isinstance(transaction, Transaction):
        amount = transaction.amount_debited
        debited_account = transaction.debited_account_name
        credited_accounts = [{"name": transaction.credited_account_name, "amount": transaction.amount_credited}]

    # Normalize credited_accounts to ensure it's a list of dictionaries
    normalized_credited_accounts = []
    if isinstance(credited_accounts, list):
        for account in credited_accounts:
            if isinstance(account, dict) and 'name' in account and 'amount' in account:
                normalized_credited_accounts.append(account)
            elif isinstance(account, str):  # If it's a string, convert it to a dictionary
                normalized_credited_accounts.append({"name": account, "amount": amount})
            else:
                logging.warning(f"Unexpected credited_account format: {account} "
                                f"in transaction ID {getattr(transaction, 'id', 'N/A')}")
    elif isinstance(credited_accounts, dict):  # Single dictionary case
        if 'name' in credited_accounts and 'amount' in credited_accounts:
            normalized_credited_accounts.append(credited_accounts)
        else:
            logging.warning(f"Unexpected credited_account format: {credited_accounts} "
                            f"in transaction ID {getattr(transaction, 'id', 'N/A')}")
    elif isinstance(credited_accounts, str):  # Single string case
        normalized_credited_accounts.append({"name": credited_accounts, "amount": amount})
    else:
        logging.warning(f"Unexpected credited_account format: {credited_accounts} "
                        f"in transaction ID {getattr(transaction, 'id', 'N/A')}")

    return amount, debited_account, normalized_credited_accounts
def mirror_amounts(amount, debited_account, credited_accounts):
    """Mirror amounts to ensure debits and credits are balanced."""
    total_debited_amount = amount if debited_account else 0
    total_credited_amount = sum(
        credited_account.get('amount', 0) if isinstance(credited_account, dict) else 0
        for credited_account in credited_accounts
    )

    if total_debited_amount != total_credited_amount:
        if total_debited_amount > total_credited_amount:
            total_credited_amount = total_debited_amount
        else:
            total_debited_amount = total_credited_amount

    return total_debited_amount, total_credited_amount

def update_account_balances(account_code, debit_amount, credit_amount, account_balances):
    """Update the account balances dictionary with the given debit and credit amounts."""
    if isinstance(account_code, list):  # Handle cases where account_code is a list
        for code in account_code:
            if isinstance(code, dict):
                code = code.get('name')  # Assuming 'name' is the key for the account code
            if code:  # Ensure the code is not empty
                account_balances[code]["debit"] += debit_amount
                account_balances[code]["credit"] += credit_amount
    elif isinstance(account_code, dict):
        account_code = account_code.get('name')  # Assuming 'name' is the key for the account code
        if account_code:  # Ensure the code is not empty
            account_balances[account_code]["debit"] += debit_amount
            account_balances[account_code]["credit"] += credit_amount
    elif account_code:  # Handle cases where account_code is a single value
        account_balances[account_code]["debit"] += debit_amount
        account_balances[account_code]["credit"] += credit_amount

# Run the application
import re
from flask import jsonify
from sqlalchemy import func

# Classification mapping for parent account code ranges
CASH_FLOW_CATEGORIES = {
    'Operating Activities': range(4000, 10000),  # 4000-9999
    'Investing Activities': range(1300, 10000),  # 1300-9999
    'Financing Activities': range(2650, 2651)    # 2650 (specific account)
}

# Function to classify cash flow based on parent account
def get_cash_flow_category(parent_account):
    """
    Classify the cash flow category based on the numeric prefix of the parent account.
    :param parent_account: String representing the parent account (e.g., '4000-Cash & Cash Equivalent').
    :return: Category name (e.g., 'Operating Activities') or None if no match is found.
    """
    # Extract numeric part of parent_account if possible (e.g., '4000-Cash & Cash Equivalent' -> '4000')
    numeric_part = re.match(r"(\d+)", str(parent_account))  # Match digits at the beginning of the string
    
    if numeric_part:
        parent_account_number = int(numeric_part.group(1))  # Extract numeric part and convert to int
    else:
        return None  # Return None if no numeric part is found

    # Iterate through the categories and check if the parent_account falls within the range
    for category, account_range in CASH_FLOW_CATEGORIES.items():
        if parent_account_number in account_range:
            return category

    # If no match found, return None (no classification)
    return None

@app.route('/cash-flow', methods=['GET'])
def get_cash_flow_statement():
    """
    Generate a cash flow statement by aggregating inflows and outflows from the database.
    :return: JSON response containing the cash flow statement.
    """
    # Initialize the results for each category
    cash_flow = {
        'Operating Activities': [],
        'Investing Activities': [],
        'Financing Activities': []
    }

    # Query for Cash Receipt Journal (Inflows)
    inflows = db.session.query(
        CashReceiptJournal.parent_account,
        func.sum(CashReceiptJournal.cash).label('total_cash'),
        func.sum(CashReceiptJournal.bank).label('total_bank')
    ).group_by(CashReceiptJournal.parent_account).all()

    # Query for Cash Disbursement Journal (Outflows)
    outflows = db.session.query(
        CashDisbursementJournal.parent_account,
        func.sum(CashDisbursementJournal.cash).label('total_cash'),
        func.sum(CashDisbursementJournal.bank).label('total_bank')
    ).group_by(CashDisbursementJournal.parent_account).all()

    # Helper function to process transactions (inflows or outflows)
    def process_transactions(transactions, transaction_type):
        """
        Process inflows or outflows and update the cash flow statement.
        :param transactions: List of grouped transactions from the database.
        :param transaction_type: 'inflow' or 'outflow'.
        """
        for transaction in transactions:
            parent_account = transaction.parent_account
            category = get_cash_flow_category(parent_account)

            # Skip if the category is None (i.e., not a valid category)
            if category is None:
                continue

            # Default to zero if no value exists
            total_cash = transaction.total_cash if transaction.total_cash else 0
            total_bank = transaction.total_bank if transaction.total_bank else 0

            # Find or create an entry for the parent account in the appropriate category
            found = False
            for entry in cash_flow[category]:
                if entry['parent_account'] == parent_account:
                    if transaction_type == 'inflow':
                        entry['inflow_cash'] += total_cash
                        entry['inflow_bank'] += total_bank
                        entry['net_cash_flow'] += total_cash
                        entry['net_bank_flow'] += total_bank
                    elif transaction_type == 'outflow':
                        entry['outflow_cash'] += total_cash
                        entry['outflow_bank'] += total_bank
                        entry['net_cash_flow'] -= total_cash
                        entry['net_bank_flow'] -= total_bank
                    found = True
                    break

            if not found:
                cash_flow[category].append({
                    'parent_account': parent_account,
                    'inflow_cash': total_cash if transaction_type == 'inflow' else 0,
                    'inflow_bank': total_bank if transaction_type == 'inflow' else 0,
                    'outflow_cash': total_cash if transaction_type == 'outflow' else 0,
                    'outflow_bank': total_bank if transaction_type == 'outflow' else 0,
                    'net_cash_flow': total_cash if transaction_type == 'inflow' else -total_cash,
                    'net_bank_flow': total_bank if transaction_type == 'inflow' else -total_bank
                })

    # Process inflows and outflows
    process_transactions(inflows, 'inflow')
    process_transactions(outflows, 'outflow')

    # Ensure the result is in the order defined by CASH_FLOW_CATEGORIES
    ordered_cash_flow = {
        'Operating Activities': cash_flow['Operating Activities'],
        'Investing Activities': cash_flow['Investing Activities'],
        'Financing Activities': cash_flow['Financing Activities']
    }

    # Return the cash flow statement as a JSON response
    return jsonify(ordered_cash_flow)

@app.route('/departmental-budget', methods=['GET'])
def departmental_budget():
    # Query the departmental budgets
    departmental_budget = db.session.query(
        Estimate.department,
        db.func.sum(Estimate.total_estimates).label('total_budget'),
        db.func.sum(Estimate.adjusted_total_estimates).label('adjusted_total_budget')
    ).group_by(Estimate.department).all()

    # Format the results with both estimated and adjusted total amounts
    report_data = [
        {
            'department': row.department,
            'total_budget': float(row.total_budget),
            'adjusted_total_budget': float(row.adjusted_total_budget) if row.adjusted_total_budget is not None else 0.0
        }
        for row in departmental_budget
    ]

    return jsonify(report_data)


@app.route('/consolidated-budget', methods=['GET'])
def consolidated_budget():
    # Query the database to fetch all estimates
    estimates = db.session.query(
        Estimate.parent_account,
        Estimate.total_estimates,
        Estimate.quantity,
        Estimate.current_estimated_price,
        Estimate.adjusted_quantity,
        Estimate.adjusted_price
    ).all()

    # Initialize variables for categorization
    capital_budget = {"total_original": 0.0, "total_adjusted": 0.0, "accounts": {}}
    receipts = {"total_original": 0.0, "total_adjusted": 0.0, "accounts": {}}
    payments = {"total_original": 0.0, "total_adjusted": 0.0, "accounts": {}}

    # Process each estimate and calculate original/adjusted totals
    for estimate in estimates:
        parent_account = estimate.parent_account
        original_total = float(estimate.total_estimates)

        # Calculate adjusted total using adjusted quantity and price
        adjusted_total = (estimate.adjusted_quantity or estimate.quantity) * (estimate.adjusted_price or estimate.current_estimated_price)

        # Categorize the parent account
        if parent_account.startswith(("14", "15", "16", "17", "18", "19")):  # Capital Budget (1400-1999)
            category = capital_budget
        elif parent_account.startswith("4"):  # Receipts (4000-4999)
            category = receipts
        elif parent_account.startswith(("5", "6", "7", "8", "9")):  # Payments (5000-9999)
            category = payments
        else:
            continue

        # Update totals for the category
        category["total_original"] += original_total
        category["total_adjusted"] += adjusted_total

        # Update account-level details
        if parent_account not in category["accounts"]:
            category["accounts"][parent_account] = {
                "original_total": 0.0,
                "adjusted_total": 0.0
            }
        category["accounts"][parent_account]["original_total"] += original_total
        category["accounts"][parent_account]["adjusted_total"] += adjusted_total

    # Convert account dictionaries to lists
    def process_accounts(category):
        category["accounts"] = [
            {"parent_account": acc, "original_total": vals["original_total"], "adjusted_total": vals["adjusted_total"]}
            for acc, vals in category["accounts"].items()
        ]

    process_accounts(capital_budget)
    process_accounts(receipts)
    process_accounts(payments)

    # Calculate surplus/deficit (Receipts - Payments) for both original and adjusted values
    original_surplus_deficit = receipts["total_original"] - payments["total_original"]
    adjusted_surplus_deficit = receipts["total_adjusted"] - payments["total_adjusted"]

    # Format the results into a structured dictionary
    report_data = {
        "capital_budget": capital_budget,
        "receipts": receipts,
        "payments": payments,
        "surplus_deficit": {
            "original_total": original_surplus_deficit,
            "adjusted_total": adjusted_surplus_deficit
        }
    }

    return jsonify(report_data)

@app.route('/budget-vs-actuals', methods=['GET'])
def budget_vs_actuals():
    try:
        # Define valid parent account prefixes
        valid_prefixes = ('4300', '4400', '4050', '5000', '7500', '1400', '4500', '1000')

        # Normalize parent_account values for comparison
        def normalize_parent_account(account):
            if account:
                numeric_prefix = ''.join(filter(str.isdigit, account))[:4]
                return numeric_prefix if len(numeric_prefix) == 4 else None
            return None

        # Step 1: Query original and adjusted budgets from the Estimate table
        estimates_query = db.session.query(
            Estimate.parent_account,
            Estimate.total_estimates.label('original_budget'),
            Estimate.adjusted_total_estimates.label('adjusted_budget')
        ).filter(
            or_(*[Estimate.parent_account.like(f"{prefix}%") for prefix in valid_prefixes])
        )
        estimates = estimates_query.all()

        logging.debug("Estimates Data:")
        for estimate in estimates:
            logging.debug(f"Parent Account: {estimate.parent_account}, Original Budget: {estimate.original_budget}")

        # Retrieve all accounts once to optimize performance
        accounts = ChartOfAccounts.query.all()

        # Helper function to get parent account details based on account code
        def get_parent_account_details(account_code):
            """Get the parent account details based on account code."""
            if account_code:
                account_code_str = str(account_code)
                for acc in accounts:
                    for subaccount in acc.sub_account_details or []:
                        if account_code_str in subaccount.get('name', ''):
                            return {
                                "parent_account": acc.parent_account,
                                "account_name": acc.account_name,
                                "account_type": acc.account_type,
                                "note_number": acc.note_number,
                            }
            return {}

        # Initialize a dictionary to track account balances
        account_balances = defaultdict(lambda: {"debit": 0.0, "credit": 0.0})

        # Query all transactions from each model
        invoices_issued = InvoiceIssued.query.all()
        invoices_received = InvoiceReceived.query.all()
        cash_receipts = CashReceiptJournal.query.all()
        cash_disbursements = CashDisbursementJournal.query.all()
        transactions = Transaction.query.all()

        # Combine all transactions into a single list
        all_transactions = (
            invoices_issued + invoices_received + cash_receipts + cash_disbursements + transactions
        )

        # Process each transaction
        for transaction in all_transactions:
            amount, debited_account, credited_accounts = extract_transaction_details(transaction)

            # Log raw credited_accounts for debugging
            logging.info(f"Processing transaction ID {getattr(transaction, 'id', 'N/A')}: "
                         f"credited_accounts = {credited_accounts}")

            # Update account balances for the debited account
            if debited_account:
                update_account_balances(debited_account, abs(amount), 0, account_balances)

            # Update account balances for credited accounts
            for credited_account in credited_accounts:
                if isinstance(credited_account, dict) and 'name' in credited_account and 'amount' in credited_account:
                    credited_amount = abs(credited_account['amount'])  # Ensure positive amount
                    update_account_balances(credited_account['name'], 0, credited_amount, account_balances)

        # Prepare actuals data based on account balances
        actuals_dict = defaultdict(float)
        for account, balances in account_balances.items():
            parent_account_details = get_parent_account_details(account)
            parent_account = parent_account_details.get('parent_account')
            if parent_account:
                normalized_prefix = normalize_parent_account(parent_account)
                if normalized_prefix in valid_prefixes:
                    actuals_dict[normalized_prefix] += abs(balances['debit'] - balances['credit'])

        # Log aggregated results
        logging.debug("Aggregated Actuals Data:")
        for prefix, amount in actuals_dict.items():
            logging.debug(f"Parent Account Prefix: {prefix}, Actual Amount: {amount}")

        # Step 3: Prepare the final report
        report_data = []
        for estimate in estimates:
            parent_account = estimate.parent_account
            normalized_parent_account = normalize_parent_account(parent_account)
            original_budget = float(estimate.original_budget)
            adjusted_budget = float(estimate.adjusted_budget or 0.0)
            final_budget = original_budget + adjusted_budget
            actual_amount = actuals_dict.get(normalized_parent_account, 0.0)
            performance_difference = final_budget - actual_amount
            utilization_difference = round((performance_difference / final_budget) * 100, 2) if final_budget > 0 else 0.0

            report_data.append({
                'parent_account': parent_account,
                'original_budget': original_budget,
                'adjusted_budget': adjusted_budget,
                'final_budget': final_budget,
                'actual_amount': actual_amount,
                'performance_difference': performance_difference,
                'utilization_difference': utilization_difference
            })

        return jsonify(report_data)

    except SQLAlchemyError as e:
        logging.error(f"Database error occurred: {str(e)}")
        return jsonify({"error": "An error occurred while processing the request."}), 500
    except Exception as e:
        logging.error(f"Unexpected error occurred: {str(e)}")
        return jsonify({"error": "An unexpected error occurred."}), 500


# ===================== HELPER FUNCTIONS =====================
def extract_transaction_details(transaction):
    """Extract transaction details (amount, debited account, credited accounts) based on type."""
    amount = 0
    debited_account = None
    credited_accounts = []

    if isinstance(transaction, InvoiceIssued):
        amount = transaction.amount
        debited_account = transaction.account_debited
        credited_accounts = transaction.account_credited or []
    elif isinstance(transaction, InvoiceReceived):
        amount = transaction.amount
        debited_account = transaction.account_debited or []
        credited_accounts = transaction.account_credited or []
    elif isinstance(transaction, CashReceiptJournal):
        amount = transaction.total
        debited_account = transaction.account_debited
        credited_accounts = transaction.account_credited or []
    elif isinstance(transaction, CashDisbursementJournal):
        amount = transaction.total
        debited_account = transaction.account_debited
        credited_accounts = transaction.account_credited or []
    elif isinstance(transaction, Transaction):
        amount = transaction.amount_debited
        debited_account = transaction.debited_account_name
        credited_accounts = [{"name": transaction.credited_account_name, "amount": transaction.amount_credited}]

    # Normalize credited_accounts to ensure it's a list of dictionaries
    normalized_credited_accounts = []
    if isinstance(credited_accounts, list):
        for account in credited_accounts:
            if isinstance(account, dict) and 'name' in account and 'amount' in account:
                normalized_credited_accounts.append(account)
            elif isinstance(account, str):  # If it's a string, convert it to a dictionary
                normalized_credited_accounts.append({"name": account, "amount": amount})
    elif isinstance(credited_accounts, dict):  # Single dictionary case
        if 'name' in credited_accounts and 'amount' in credited_accounts:
            normalized_credited_accounts.append(credited_accounts)
    elif isinstance(credited_accounts, str):  # Single string case
        normalized_credited_accounts.append({"name": credited_accounts, "amount": amount})

    return abs(amount), debited_account, normalized_credited_accounts  # Ensure positive amount


def update_account_balances(account_code, debit_amount, credit_amount, account_balances):
    """Update the account balances dictionary with the given debit and credit amounts."""
    if isinstance(account_code, list):  # Handle cases where account_code is a list
        for code in account_code:
            if isinstance(code, dict):
                code = code.get('name')  # Assuming 'name' is the key for the account code
            if code:  # Ensure the code is not empty
                account_balances[code]["debit"] += abs(debit_amount)  # Ensure positive debit
                account_balances[code]["credit"] += abs(credit_amount)  # Ensure positive credit
    elif isinstance(account_code, dict):
        account_code = account_code.get('name')  # Assuming 'name' is the key for the account code
        if account_code:  # Ensure the code is not empty
            account_balances[account_code]["debit"] += abs(debit_amount)  # Ensure positive debit
            account_balances[account_code]["credit"] += abs(credit_amount)  # Ensure positive credit
    elif account_code:  
        account_balances[account_code]["debit"] += abs(debit_amount)  
        account_balances[account_code]["credit"] += abs(credit_amount)  
    
if __name__ == '__main__':
    app.run(debug=True)
