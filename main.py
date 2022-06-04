from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort
from flask_gravatar import Gravatar
import smtplib
import os

Email = "wassi.in786@gmail.com"
password = "Asiya"


def send_mail(name, email, phone, message):
    email_message = f"Subject:New Msg\n\n Name: {name}\n Email: {email}\n Phone:{phone}\n Message:{message}"
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(Email, password)
        connection.sendmail(Email, Email, email_message)


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager= LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CONFIGURE TABLES


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email= db.Column(db.String(100), unique=True)
    password= db.Column(db.String(100))
    name=db.Column(db.String(1000))
        #This will act like list of BlogPosts objects attached to each user
        #author refers to 'author ' property in Blogpost class.
    posts = relationship('BlogPost', back_populates="author")

    comments = relationship("Comment" , back_populates='comment_author')

db.create_all()


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    #create foreign key "users.id" the users refer to the table name of User
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    #create reference to user object, the posts refers to the post property in user class


    author = relationship("User", back_populates='posts')

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    #*****************Parent relationship*************************#
    comments = relationship("Comment", back_populates="parent_post")
db.create_all()

class Comment(db.Model):
    __tablename__ ="comments"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship("User", back_populates="comments")

    #*******************Child relationship****************#
    post_id=db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship('BlogPost', back_populates="comments")
    text = db.Column(db.Text, nullable=False)
db.create_all()



def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return func(*args,**kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("You have already signed up with that email, Try logging in")
            return redirect(url_for('login'))

        hashed_and_salted_password=generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user=User(
            email=form.email.data,
            password=hashed_and_salted_password,
            name=form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login',methods=['GET','POST'])
def login():
    form= LoginForm()
    if form.validate_on_submit():
        email= form.email.data
        password= form.password.data

        user= User.query.filter_by(email=email).first()

        if not user:
            flash("That email doesn't exist, try again!")
            return redirect(url_for('login'))
        elif not  check_password_hash(user.password, password):
            flash('incorrect password')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment on this post")
            return redirect(url_for("login"))

        new_comment = Comment(
            text = comment_form.comment_text.data,
            comment_author = current_user,
            parent_post = requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact", methods=['GET','POST'])
def contact():
    if request.method == 'POST':
        name = request.form["Name"]
        email = request.form["Email"]
        phone = request.form["Phone"]
        message = request.form["Message"]
        send_mail(name, email, phone, message)
        return render_template("contact.html", msg_sent=True, current_user=current_user)

    return render_template("contact.html", msg_sent=False, current_user=current_user)


@app.route("/new-post", methods=['GET','POST'])
@admin_only
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
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=['GET','POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)

