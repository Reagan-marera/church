"""empty message

Revision ID: 23151009b0aa
Revises: a95ad4b9715f
Create Date: 2025-01-30 21:45:42.492938

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '23151009b0aa'
down_revision = 'a95ad4b9715f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('customer',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=100), nullable=False),
    sa.Column('phone', sa.String(length=15), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('payee',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('parent_account', sa.String(length=150), nullable=False),
    sa.Column('account_name', sa.String(length=100), nullable=False),
    sa.Column('account_type', sa.String(length=50), nullable=False),
    sa.Column('sub_account_details', sa.JSON(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('payee')
    op.drop_table('customer')
    # ### end Alembic commands ###
