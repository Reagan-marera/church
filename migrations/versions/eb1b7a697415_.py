"""empty message

Revision ID: eb1b7a697415
Revises: 0f9655cbd569
Create Date: 2025-03-10 21:07:19.003767

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'eb1b7a697415'
down_revision = '0f9655cbd569'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('estimate',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('department', sa.String(length=100), nullable=False),
    sa.Column('procurement_method', sa.String(length=100), nullable=False),
    sa.Column('item_specifications', sa.String(length=255), nullable=False),
    sa.Column('unit_of_measure', sa.String(length=50), nullable=False),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('current_estimated_price', sa.Float(), nullable=False),
    sa.Column('total_estimates', sa.Float(), nullable=False),
    sa.Column('parent_account', sa.String(length=100), nullable=False),
    sa.Column('sub_account', sa.String(length=100), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('estimate')
    # ### end Alembic commands ###
