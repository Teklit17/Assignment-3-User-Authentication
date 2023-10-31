"""Initial migration

Revision ID: 51874961dc53
Revises: 
Create Date: 2023-10-31 11:13:31.614139

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '51874961dc53'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('post',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=100), nullable=True),
    sa.Column('content', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('post')
    # ### end Alembic commands ###
