from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from sqlalchemy.exc import IntegrityError
from forms import RegisterForm, LoginForm, FeedbackForm


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///feedbacks"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)


@app.route('/')
def home_page():
    """Shows all feedbacks"""

    feedbacks = Feedback.query.all()
    return render_template('index.html', feedbacks = feedbacks)

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """Shows form to add user, adds user to DB"""

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = User.register(username, password, email, first_name, last_name)

        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username/email taken.  Please pick another')
            return render_template('register.html', form=form)
        
        session['username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', "success")
        return redirect(f'/users/{new_user.username}')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    """Shows login form, check if credentials are valid, logs user in"""

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f"Welcome Back, {user.username}!", "primary")
            session['username'] = user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = ['Invalid username/password.']

    return render_template('login.html', form=form)

@app.route('/users/<username>')
def show_user_details(username):
    """Shows users info and their feedbacks"""

    if "username" not in session:
        flash("Please login first!", "danger")
        return redirect('/')
    if session['username'] != username:
        flash("Access denied", "danger")
        return redirect('/')
    user = User.query.filter_by(username=username).first()
    return render_template('my_account.html', user = user)

@app.route('/logout', methods = ["POST"])
def logout_user():
    """Logs user out"""

    user = session['username']
    session.pop('username')
    flash(f"Goodbye, {user}!", "info")
    return redirect('/')

@app.route('/users/<username>/delete', methods=["POST"])
def delete_user(username):
    """Deletes user's account and all their feedbacks"""

    if "username" not in session:
        flash("Please login first!", "danger")
        return redirect('/')
    if session['username'] != username:
        flash("Access denied", "danger")
        return redirect('/')
    Feedback.query.filter_by(username=username).delete()
    User.query.filter_by(username=username).delete()
    session.pop('username')
    db.session.commit()
    return redirect('/')

@app.route('/users/<username>/feedbacks/add', methods=['GET', 'POST'])
def add_feedback(username):
    """Shows form to add feedback, adds feedback to DB"""

    if "username" not in session:
        flash("Please login first!", "danger")
        return redirect('/')
    if session['username'] != username:
        flash("Access denied", "danger")
        return redirect('/')
    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        new_feedback = Feedback(title = title, content = content, username = username)
        db.session.add(new_feedback)
        db.session.commit()
        return redirect(f'users/{username}')
    return render_template('add_feedback.html', form=form)

@app.route('/feedback/<int:f_id>/update', methods=['GET', 'POST'])
def update_feedback(f_id):
    """Shows prefilled update form, saves updated feedback in DB"""

    feedback = Feedback.query.get_or_404(f_id)
    if "username" not in session:
        flash("Unathorized", "danger")
        return redirect('/')
    if session['username'] != feedback.username:
        flash("Access denied", "danger")
        return redirect('/')
    form = FeedbackForm(obj=feedback)
    if form.validate_on_submit():
        feedback.title=form.title.data
        feedback.content=form.content.data
        feedback.username=feedback.username
        db.session.commit()
        return redirect(f'/users/{feedback.username}')
    return render_template('edit_feedback.html', form = form, feedback=feedback)

@app.route('/feedback/<int:f_id>/delete', methods=['POST'])
def delete_feedback(f_id):
    """Deletes feedback"""
    
    fb = Feedback.query.get_or_404(f_id)
    if "username" not in session:
        flash("Unathorized", "danger")
        return redirect('/')
    if session['username'] != fb.username:
        flash("Access denied", "danger")
        return redirect('/')
    Feedback.query.filter_by(id = f_id).delete()
    db.session.commit()
    return redirect(f'/users/{session["username"]}')
