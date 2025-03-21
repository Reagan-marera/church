"""empty message

Revision ID: 076a41fe5b21
Revises: 975c3a79cb3a
Create Date: 2025-03-17 12:39:27.814425

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '076a41fe5b21'
down_revision = '975c3a79cb3a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('adjustment',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('estimate_id', sa.Integer(), nullable=False),
    sa.Column('adjustment_type', sa.String(length=50), nullable=False),
    sa.Column('adjustment_value', sa.Float(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('created_by', sa.String(length=100), nullable=True),
    sa.ForeignKeyConstraint(['estimate_id'], ['estimate.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('adjustment')
    # ### end Alembic commands ###
