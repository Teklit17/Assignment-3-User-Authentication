"""empty message

Revision ID: 84b2014a796d
Revises: e365f6c7db81
Create Date: 2023-11-01 21:25:02.175659

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '84b2014a796d'
down_revision = 'e365f6c7db81'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('salt', sa.String(length=29), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('salt')

    # ### end Alembic commands ###
