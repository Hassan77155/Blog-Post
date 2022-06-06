import os
from datetime import date
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
# from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

from forms import CreatePostForm, RegisterForm, LoginForm

# from flask_gravatar import Gravatar


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("Blog_Secret_Key")
ckeditor = CKEditor(app)
Bootstrap(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user):
    return User.query.get(user)


# CONNECT TO DB

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


# User table


class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(400), nullable=False)

    def get_id(self):
        try:
            return str(self.user_id)
        except AttributeError:
            raise NotImplementedError(
                "No `id` attribute - override `get_id`") from None


db.create_all()


def admins_only(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.user_id == 1:
            pass
        else:
            return abort(403)

        return func(*args, **kwargs)

    return decorated_view


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["POST", "GET"])
def register():
    # Create a register form
    form = RegisterForm()
    # If the user submits a valid form
    if form.validate_on_submit():
        # Make sure the email is not already used
        email = request.form.get("email")
        # This will get a list
        email_in_db = User.query.filter_by(email=email).all()
        # If the list is empty that means the email isn't used
        if email_in_db:
            flash("This email is already signed up!")
            return redirect(url_for('login'))
        # Hash the password
        hashed_password = generate_password_hash(
            password=request.form.get("password"),
            method="pbkdf2:sha256",
            salt_length=8
        )
        # Create a new user
        new_user = User(
            email=email,
            password=hashed_password,
            name=request.form.get("name")
        )
        # Add the user to db and commit changes
        db.session.add(new_user)
        db.session.commit()
        # Login in new user
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    # Create a login form
    login_form = LoginForm()
    # When the user press login btn
    if login_form.validate_on_submit():
        # Get the email and password the user provided
        email = request.form.get("email")
        password = request.form.get("password")
        # Check if email in db
        email_in_db = User.query.filter_by(email=email).first()
        print(email_in_db)
        if email_in_db:
            # Check if password is correct
            if check_password_hash(email_in_db.password, password):
                # Login in the user
                login_user(email_in_db)
                # Go to home page
                return redirect(url_for("get_all_posts"))
            # If password isn't correct
            flash("Wrong Password")
            return redirect(url_for("login"))
        # If email isn't correct
        flash("Wrong Email")
        return redirect(url_for("login"))
    # When the method is get show the login form
    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post")
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admins_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admins_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
