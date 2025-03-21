"""empty message

Revision ID: 5c3a7ce69dd8
Revises: 076a41fe5b21
Create Date: 2025-03-17 16:46:56.114721

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5c3a7ce69dd8'
down_revision = '076a41fe5b21'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('estimate', schema=None) as batch_op:
        batch_op.add_column(sa.Column('adjusted_quantity', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('adjusted_price', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('adjusted_total_estimates', sa.Float(), nullable=True))
        batch_op.alter_column('department',
               existing_type=sa.VARCHAR(length=100),
               type_=sa.String(length=255),
               existing_nullable=False)
        batch_op.alter_column('procurement_method',
               existing_type=sa.VARCHAR(length=100),
               type_=sa.String(length=255),
               nullable=False)
        batch_op.alter_column('quantity',
               existing_type=sa.INTEGER(),
               type_=sa.Float(),
               existing_nullable=False)
        batch_op.alter_column('parent_account',
               existing_type=sa.VARCHAR(length=100),
               type_=sa.String(length=255),
               nullable=True)
        batch_op.alter_column('sub_account',
               existing_type=sa.VARCHAR(length=100),
               type_=sa.String(length=255),
               nullable=True)
        batch_op.drop_column('actual_expenditure')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('estimate', schema=None) as batch_op:
        batch_op.add_column(sa.Column('actual_expenditure', sa.FLOAT(), nullable=True))
        batch_op.alter_column('sub_account',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=100),
               nullable=False)
        batch_op.alter_column('parent_account',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=100),
               nullable=False)
        batch_op.alter_column('quantity',
               existing_type=sa.Float(),
               type_=sa.INTEGER(),
               existing_nullable=False)
        batch_op.alter_column('procurement_method',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=100),
               nullable=True)
        batch_op.alter_column('department',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=100),
               existing_nullable=False)
        batch_op.drop_column('adjusted_total_estimates')
        batch_op.drop_column('adjusted_price')
        batch_op.drop_column('adjusted_quantity')

    # ### end Alembic commands ###
