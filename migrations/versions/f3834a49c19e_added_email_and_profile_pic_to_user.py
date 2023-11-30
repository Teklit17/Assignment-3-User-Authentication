"""Added email and profile_pic to User

Revision ID: f3834a49c19e
Revises: 10b8625d1cdd
Create Date: 2023-11-08 07:48:59.865577

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f3834a49c19e'
down_revision = '10b8625d1cdd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email', sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column('profile_pic', sa.String(length=255), nullable=True))
        batch_op.create_unique_constraint('uq_user_email', ['email'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')
        batch_op.drop_column('profile_pic')
        batch_op.drop_column('email')

    # ### end Alembic commands ###