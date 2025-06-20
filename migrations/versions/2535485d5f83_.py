"""empty message

Revision ID: 2535485d5f83
Revises: 4485e2840e2d
Create Date: 2025-06-14 18:42:43.276256

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2535485d5f83'
down_revision = '4485e2840e2d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('bank_reconciliation', sa.Column('is_completed', sa.Boolean(), nullable=True))
    op.add_column('bank_reconciliation', sa.Column('completed_at', sa.DateTime(), nullable=True))
    op.drop_column('bank_reconciliation', 'created_at')
    op.add_column('bank_reconciliation_item', sa.Column('description', sa.String(length=255), nullable=True))
    op.add_column('bank_reconciliation_item', sa.Column('cleared_date', sa.Date(), nullable=True))
    op.add_column('bank_reconciliation_item', sa.Column('is_reconciled', sa.Boolean(), nullable=True))
    op.add_column('bank_reconciliation_item', sa.Column('reference_number', sa.String(length=50), nullable=True))
    op.add_column('bank_reconciliation_item', sa.Column('counterparty', sa.String(length=100), nullable=True))
    op.drop_column('bank_reconciliation_item', 'notes')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('bank_reconciliation_item', sa.Column('notes', sa.VARCHAR(length=255), nullable=True))
    op.drop_column('bank_reconciliation_item', 'counterparty')
    op.drop_column('bank_reconciliation_item', 'reference_number')
    op.drop_column('bank_reconciliation_item', 'is_reconciled')
    op.drop_column('bank_reconciliation_item', 'cleared_date')
    op.drop_column('bank_reconciliation_item', 'description')
    op.add_column('bank_reconciliation', sa.Column('created_at', sa.DATETIME(), nullable=True))
    op.drop_column('bank_reconciliation', 'completed_at')
    op.drop_column('bank_reconciliation', 'is_completed')
    # ### end Alembic commands ###
