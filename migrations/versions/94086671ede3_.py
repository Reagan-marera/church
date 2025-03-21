"""empty message

Revision ID: 94086671ede3
Revises: 5c3a7ce69dd8
Create Date: 2025-03-17 20:55:00.326455

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '94086671ede3'
down_revision = '5c3a7ce69dd8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('invoice_issued', schema=None) as batch_op:
        batch_op.add_column(sa.Column('parent_account', sa.String(length=150), nullable=True))

    with op.batch_alter_table('invoice_received', schema=None) as batch_op:
        batch_op.add_column(sa.Column('parent_account', sa.String(length=150), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('invoice_received', schema=None) as batch_op:
        batch_op.drop_column('parent_account')

    with op.batch_alter_table('invoice_issued', schema=None) as batch_op:
        batch_op.drop_column('parent_account')

    # ### end Alembic commands ###
