from flask import Flask, jsonify, request
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
import datetime
import jwt
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from functools import wraps


load_dotenv(override=True)
app = Flask(__name__)

root_db = os.getenv("ROOT")
pass_db = os.getenv("PASS")
localhost_db = os.getenv("LOCALHOST")
postgree_port_db = os.getenv("POSTGREE_PORT")
db_name = os.getenv("DATABASE_NAME")
secret_key = os.getenv("SECRET_KEY")

app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://{root_db}:{pass_db}@{localhost_db}:{postgree_port_db}/{db_name}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = f"{secret_key}"
db = SQLAlchemy(app)
ma = Marshmallow(app)


users_movies = db.Table("users_movies",
                        db.Column("movies", db.Integer, db.ForeignKey(
                            "movies.id"), primary_key=True),
                        db.Column("users", db.Integer, db.ForeignKey(
                            "users.id"), primary_key=True)
                        )


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    username = db.Column(db.String(84), nullable=False)
    email = db.Column(db.String(84), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f"<User : {self.username}"


class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "username", "email")


class MovieSchema(ma.Schema):
    class Meta:
        fields = ("id", "title", "description", "genre")


class Movie(db.Model):
    __tablename__ = "movies"
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    title = db.Column(db.String(84), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    genre = db.Column(db.String(84), nullable=False)
    users_movies = db.relationship("User", secondary=users_movies, lazy="subquery",
                                   backref=db.backref("movies", lazy=True))

    def __init__(self, title, description, genre):
        self.title = title
        self.description = description
        self.genre = genre

    def __repr__(self):
        return f"<User : {self.title}"


user_share_schema = UserSchema()
users_share_schema = UserSchema(many=True)
movie_share_schema = UserSchema()
movies_share_schema = UserSchema(many=True)


Migrate(app, db)


def jwt_requried(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None

        if "authorization" in request.headers:
            token = request.headers["authorization"]

        if not token:
            return jsonify({"error": "You are not authorized"}), 403

        if not "Bearer" in token:
            return jsonify({"error": "invalid token"}), 401
        try:
            token_pure = token.replace("Bearer ", "")
            decoded = jwt.decode(
                token_pure, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.query.get(decoded["id"])
        except Exception as e:
            print(f"{e}")
            return jsonify({"error": "This token is invalid"})

        return f(current_user=current_user, *args, **kwargs)
    return wrapper


@app.shell_context_processor
def make_shell_context():
    return dict(
        app=app,
        db=db,
        User=User
    )


@app.route("/", methods=["GET"])
def index():
    return "Testing server"


@app.route("/api/register", methods=["POST"])
def register():
    if request.method == "POST":
        username = request.json["username"]
        email = request.json["email"]
        password = request.json["password"]

        user = User(username, email, password)
        db.session.add(user)
        db.session.commit()

        result = user_share_schema.dump(
            User.query.filter_by(email=email).first())

        return jsonify(result)


@app.route("/api/login", methods=["POST"])
def login():
    email = request.json["email"]
    password = request.json["password"]

    user = User.query.filter_by(email=email).first_or_404()

    if not user.verify_password(password):
        return jsonify({
            "error": "Your email or your password is incorrect"
        }), 403

    payload = {
        "id": user.id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=10)
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({"token": token})


@app.route("/api/users")
@jwt_requried
def all_users(current_user):
    result = users_share_schema.dump(
        User.query.all()
    )

    return jsonify(result)


# @app.route("/api/movie/create", methods=["POST"])
# @jwt_requried
# def create_movie(current_user):
#     body = request.get_json()
#     try:
#         title = body["title"]
#         description = body["description"]
#         genre = body["genre"]
#         user = current_user
#         movie = Movie(title=title, description=description, genre=genre)
#         db.session.add(movie)
#         db.session.commit()
#         movie.users_movies.append(user)
#         db.session.commit()

#         return jsonify({"msg": "The movie was created with success"})

#     except Exception as e:
#         print(f"{e}")
#         return jsonify({"error": "This token is invalid"})

@app.route("/api/movie/create", methods=["POST"])
@jwt_requried
def create_movie(current_user):
    body = request.get_json()
    try:
        title = body["title"]
        description = body["description"]
        genre = body["genre"]
        movie = Movie(title=title, description=description, genre=genre)
        db.session.add(movie)
        db.session.commit()
        return jsonify({"msg": "The movie was created with success"})

    except Exception as e:
        print(f"{e}")
        return jsonify({"error": "This token is invalid"})


@app.route("/api/user/<int:user_id>/movie/<movie_id>", methods=["POST"])
@jwt_requried
def user_movie(current_user, user_id, movie_id):
    print("here --->", type(current_user.id))
    print(type(user_id))
    print(type(movie_id))
    try:

        movie = Movie.query.filter_by(id=movie_id).first()
        print("movie ->", movie)
        print("user_id ->", user_id)
        print("current_user.id ->" + current_user.id)
        movie.users_movies.append(user_id)
        db.session.commit()
        return jsonify({"msg": f"The was associated with {movie.title} success"})

    except Exception as e:
        print(f"{e}")
        return jsonify({"error": "This token is invalid"})
