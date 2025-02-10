"""Added new fields to transaction table

Revision ID: d23e09889179
Revises: 
Create Date: 2025-02-02 21:35:38.481347

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd23e09889179'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transaction', schema=None) as batch_op:
        batch_op.drop_column('credited_account_id')
        batch_op.drop_column('debited_account_id')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transaction', schema=None) as batch_op:
        batch_op.add_column(sa.Column('debited_account_id', sa.INTEGER(), nullable=False))
        batch_op.add_column(sa.Column('credited_account_id', sa.INTEGER(), nullable=False))

    # ### end Alembic commands ###
