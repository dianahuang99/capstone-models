from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

bcrypt = Bcrypt()
db = SQLAlchemy()


class User(db.Model):
    """User in the system."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True,)

    username = db.Column(db.Text, nullable=False, unique=True,)

    zip_code = db.Column(db.Interger,)

    password = db.Column(db.Text, nullable=False,)

    saved_orgs = db.relationship("Organization", secondary="org_likes")

    saved_pets = db.relationship("Pet", secondary="pet_likes")

    @classmethod
    def signup(cls, username, email, password, image_url):
        """Sign up user.

        Hashes password and adds user to system.
        """

        hashed_pwd = bcrypt.generate_password_hash(password).decode("UTF-8")

        user = User(username=username, email=email, password=hashed_pwd)

        db.session.add(user)
        return user

    @classmethod
    def authenticate(cls, username, password):
        """Find user with `username` and `password`.

        This is a class method (call it on the class, not an individual user.)
        It searches for a user whose password hash matches this password
        and, if it finds such a user, returns that user object.

        If can't find matching user (or if password is wrong), returns False.
        """

        user = cls.query.filter_by(username=username).first()

        if user:
            is_auth = bcrypt.check_password_hash(user.password, password)
            if is_auth:
                return user

        return False


class OrgLikes(db.Model):
    """Mapping user likes to organizations."""

    __tablename__ = "org_likes"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="cascade"))

    org_id = db.Column(
        db.Integer, db.ForeignKey("organizations.id", ondelete="cascade")
    )


class PetLikes(db.Model):
    """Mapping user likes to pets."""

    __tablename__ = "pet_likes"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="cascade"))

    pet_id = db.Column(db.Integer, db.ForeignKey("pets.id", ondelete="cascade"))


class Organization(db.Model):
    """An individual organization."""

    __tablename__ = "organizations"

    id = db.Column(db.Integer, primary_key=True,)


class Pet(db.Model):
    """An individual pet."""

    __tablename__ = "pets"

    id = db.Column(db.Integer, primary_key=True,)


def connect_db(app):
    """Connect this database to provided Flask app.

    You should call this in your Flask app.
    """

    db.app = app
    db.init_app(app)
