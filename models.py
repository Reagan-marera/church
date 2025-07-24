from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import UniqueConstraint
from datetime import datetime

# Initialize the database
db = SQLAlchemy()

# User Model with role-based access
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  

    # Password methods
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Relationship to other models
    cash_disbursements = db.relationship('CashDisbursementJournal', back_populates='created_by_user')
    cash_receipts = db.relationship('CashReceiptJournal', back_populates='created_by_user')
    invoices_issued = db.relationship('InvoiceIssued', back_populates='user')
    invoices_received = db.relationship('InvoiceReceived', back_populates='user')
    reconciliations = db.relationship('CashbookReconciliation', back_populates='creator')
    def __repr__(self):
        return f'<User {self.username} - {self.role}>'

# ChartOfAccounts Model
class ChartOfAccounts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_account = db.Column(db.String(150), nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)  # E.g., Asset, Liability, Equity
    sub_account_details = db.Column(db.JSON, nullable=True)  # Storing subaccounts as JSON
    note_number = db.Column(db.String(50), nullable=True)  # New field for note number

    # Foreign key to link to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('chart_of_accounts', lazy=True))
    invoices_received = db.relationship('InvoiceReceived', back_populates='chart_of_account')

    # Foreign key to link to a parent account (self-referential relationship)
    parent_account_id = db.Column(db.Integer, db.ForeignKey('chart_of_accounts.id'), nullable=True)
    parent_account_rel = db.relationship('ChartOfAccounts', remote_side=[id], backref=db.backref('sub_accounts', lazy=True))

    def __repr__(self):
        return f'<ChartOfAccounts {self.parent_account} - {self.account_name}>'

class Estimate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(255), nullable=False)
    procurement_method = db.Column(db.String(255), nullable=False)
    item_specifications = db.Column(db.String(255), nullable=False)
    unit_of_measure = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    current_estimated_price = db.Column(db.Float, nullable=False)
    total_estimates = db.Column(db.Float, nullable=False)
    adjusted_quantity = db.Column(db.Float, nullable=True)
    adjusted_price = db.Column(db.Float, nullable=True)
    adjusted_total_estimates = db.Column(db.Float, nullable=True)
    parent_account = db.Column(db.String(255), nullable=True)
    sub_account = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('estimates', lazy=True))

    def to_dict(self):
        return {
            "id": self.id,
            "department": self.department,
            "procurement_method": self.procurement_method,
            "item_specifications": self.item_specifications,
            "unit_of_measure": self.unit_of_measure,
            "quantity": self.quantity,
            "current_estimated_price": self.current_estimated_price,
            "total_estimates": self.total_estimates,
            "adjusted_quantity": self.adjusted_quantity,
            "adjusted_price": self.adjusted_price,
            "adjusted_total_estimates": self.adjusted_total_estimates,
            "parent_account": self.parent_account,
            "sub_account": self.sub_account,
        }

class Adjustment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    estimate_id = db.Column(db.Integer, db.ForeignKey('estimate.id'), nullable=False)  # Foreign key to Estimate
    adjustment_type = db.Column(db.String(50), nullable=False)  # e.g., 'price' or 'quantity'
    adjustment_value = db.Column(db.Float, nullable=False)  # Positive or negative adjustment
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Timestamp of adjustment
    created_by = db.Column(db.String(100), nullable=True)  # Optional: Who made the adjustment

    def __repr__(self):
        return f'<Adjustment {self.adjustment_type}: {self.adjustment_value} on {self.created_at}>'

# Payee Model
class Payee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_account = db.Column(db.String(150), nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)  # E.g., Asset, Liability, Equity
    sub_account_details = db.Column(db.JSON, nullable=True)  # Storing subaccounts as JSON

    # Foreign key to link to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('payees', lazy=True))

    def __repr__(self):
        return f'<Payee {self.parent_account} - {self.account_name}>'

# Customer Model
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)  # Ensure this field exists
    balance = db.Column(db.Float, default=0.0)  # Track customer balance
    parent_account = db.Column(db.String(150), nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)  # E.g., Asset, Liability, Equity
    sub_account_details = db.Column(db.JSON, nullable=True)  # Storing subaccounts as JSON

    # Foreign key to link to User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('customers', lazy=True))

    def __repr__(self):
        return f'<Customer {self.parent_account} - {self.account_name}>'

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    credited_account_name = db.Column(db.String(100), nullable=False)
    debited_account_name = db.Column(db.String(100), nullable=False)
    amount_credited = db.Column(db.Float, nullable=False)
    amount_debited = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    date_issued = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Add this line
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))  # Add this line

class InvoiceIssued(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_number = db.Column(db.String(50), nullable=False)
    date_issued = db.Column(db.Date, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    amount = db.Column(db.Integer, nullable=False)
    parent_account = db.Column(db.String(150), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key linking to User table
    user = db.relationship('User', back_populates='invoices_issued')
    account_debited = db.Column(db.String(100), nullable=True)
    account_credited = db.Column(db.JSON, nullable=True)
    name = db.Column(db.String(50), nullable=True)
    manual_number = db.Column(db.String(50), nullable=True)  # Change to String type (VARCHAR equivalent)

    # Add composite unique constraint on user_id and invoice_number
    __table_args__ = (
        db.UniqueConstraint('user_id', 'invoice_number', name='unique_invoice_per_user'),
    )

    # Adding relationship to CashReceiptJournal
    receipts = db.relationship('CashReceiptJournal', back_populates='selected_invoice', lazy=True)

    def __repr__(self):
        return f'<InvoiceIssued {self.invoice_number}>'

class InvoiceReceived(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_number = db.Column(db.String(50), nullable=False)
    date_issued = db.Column(db.Date, nullable=False)
    name = db.Column(db.String(50), nullable=True)
    parent_account = db.Column(db.String(150), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    amount = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key linking to User table
    coa_id = db.Column(db.Integer, db.ForeignKey('chart_of_accounts.id'), nullable=True)
    chart_of_account = db.relationship('ChartOfAccounts', back_populates='invoices_received')
    user = db.relationship('User', back_populates='invoices_received')
    account_debited = db.Column(db.JSON, nullable=True)
    account_credited = db.Column(db.String(100), nullable=True)
    grn_number = db.Column(db.String(20), nullable=True)

    # Add composite unique constraint on user_id and invoice_number
    __table_args__ = (
        db.UniqueConstraint('user_id', 'invoice_number', name='unique_invoice_per_user'),
    )

    def __repr__(self):
        return f'<InvoiceReceived {self.invoice_number}>'

class CashReceiptJournal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_date = db.Column(db.Date, nullable=False)
    receipt_no = db.Column(db.String(50), nullable=False)
    ref_no = db.Column(db.String(50), nullable=True)
    from_whom_received = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    department = db.Column(db.String(250), nullable=True)

    receipt_type = db.Column(db.String(50), nullable=False)  # Add receipt_type
    account_debited = db.Column(db.String(100), nullable=True)
    account_credited = db.Column(db.String(100), nullable=True)
    parent_account = db.Column(db.String(150), nullable=True)
    bank = db.Column(db.String(100), nullable=True)
    cash = db.Column(db.Float, nullable=True)
    total = db.Column(db.Float, nullable=False)
    cashbook = db.Column(db.String(250), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_by_user = db.relationship('User', back_populates='cash_receipts')
    name = db.Column(db.String(50), nullable=True)
    selected_invoice_id = db.Column(db.Integer, db.ForeignKey('invoice_issued.id'), nullable=True)  # Link to InvoiceIssued
    selected_invoice = db.relationship('InvoiceIssued', back_populates='receipts')
    manual_number = db.Column(db.String(50), nullable=True)  # Change to String type (VARCHAR equivalent)

    __table_args__ = (
        UniqueConstraint('created_by', 'receipt_no', name='unique_receipt_per_user'),
    )

    def __repr__(self):
        return f'<CashReceiptJournal {self.receipt_no}>'

    def save(self):
        # Ensure that cash and bank are numeric before calculation
        if not isinstance(self.cash, (int, float)) or not isinstance(self.bank, (int, float)):
            raise ValueError("Cash and Bank values must be numeric.")

        # Calculate total before saving
        self.total = self.cash + self.bank
        db.session.add(self)
        db.session.commit()

# Cash Disbursement Journal Model
class CashDisbursementJournal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    disbursement_date = db.Column(db.Date, nullable=False)
    cheque_no = db.Column(db.String(50), nullable=False)  # Removed unique constraint
    p_voucher_no = db.Column(db.String(50), nullable=True)
    name = db.Column(db.String(50), nullable=True)
    to_whom_paid = db.Column(db.String(100), nullable=False)
    payment_type = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    department = db.Column(db.String(250), nullable=True)

    account_credited = db.Column(db.String(100), nullable=False)
    account_debited = db.Column(db.String(100), nullable=True)
    cashbook = db.Column(db.String(250), nullable=True)
    parent_account = db.Column(db.String(150), nullable=True)
    cash = db.Column(db.Float, nullable=False, default=0.0)
    bank = db.Column(db.Float, nullable=False, default=0.0)  # Updated to Float for numeric values
    total = db.Column(db.Float, nullable=False, default=0.0)  # Added total column with a default value
    manual_number = db.Column(db.String(50), nullable=True)  # Change to String type (VARCHAR equivalent)

    # Foreign key to User
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_by_user = db.relationship('User', back_populates='cash_disbursements')

    def __repr__(self):
        return f'<CashDisbursementJournal {self.cheque_no}>'

    def save(self):
        # Ensure that cash and bank are numeric before calculation
        if not isinstance(self.cash, (int, float)) or not isinstance(self.bank, (int, float)):
            raise ValueError("Cash and Bank values must be numeric.")

        # Calculate total before saving
        self.total = self.cash + self.bank
        db.session.add(self)
        db.session.commit()

    # Adding a UniqueConstraint for the combination of created_by and cheque_no
    __table_args__ = (
        UniqueConstraint('created_by', 'cheque_no', name='unique_receipt_per_user'),
    )

class CashbookReconciliation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False)  # 'receipt' or 'payment'
    bank_account = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(255), nullable=True)
    transaction_details = db.Column(db.String(255), nullable=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    manual_number = db.Column(db.String(50), nullable=True)  # Optional, for manual tracking

    # Foreign key to User
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', back_populates='reconciliations')

    def __repr__(self):
        return f"<CashbookReconciliation {self.date} {self.transaction_type} {self.amount}>"

# OTP Model
class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f'<OTP {self.email}>'
