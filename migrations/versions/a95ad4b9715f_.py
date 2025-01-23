"""empty message

Revision ID: a95ad4b9715f
Revises: 
Create Date: 2025-01-22 12:54:40.745934

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a95ad4b9715f'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Add column with a default value
    with op.batch_alter_table('invoice_issued') as batch_op:
        batch_op.add_column(sa.Column('invoice_type', sa.String(length=100), nullable=False, server_default=''))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('invoice_issued', schema=None) as batch_op:
        batch_op.drop_column('invoice_type')

    # ### end Alembic commands ###
