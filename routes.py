from flask import render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app import app, db, bcrypt, login_manager, mail
from flask_mail import Message
from models import User, Poll, Vote, AnonymousUser
import os, base64, random, re

# ----------------- LOGIN MANAGER -----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ----------------- AUTH -----------------
@app.route('/')
def homepage():
    return render_template("homepage.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('homepage'))
        flash('Invalid credentials.', 'danger')
    return render_template("login.html")

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# ----------------- OTP -----------------
@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'status': '❌ Email is required.'}), 400

    otp = str(random.randint(100000, 999999))
    session['otp'] = otp

    try:
        msg = Message("Your TrustVote OTP",
                      sender=app.config['MAIL_DEFAULT_SENDER'],
                      recipients=[email])
        msg.body = f"Your OTP for voting is: {otp}"
        mail.send(msg)
        return jsonify({'status': '✅ OTP sent to your email.'}), 200
    except Exception as e:
        print("OTP sending error:", e)
        return jsonify({'status': '❌ Failed to send OTP.'}), 500


@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    entered = request.json.get('otp')
    valid = session.get('otp') == entered
    return jsonify({"verified": valid, "status": "✅ OTP Verified!" if valid else "❌ Invalid OTP."})

# ----------------- REGISTRATION -----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form.get('phone')
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        photo_data = request.form['photoData']

        filename = f'{name.split()[0].lower()}.png'
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, "wb") as f:
            f.write(base64.b64decode(photo_data.split(',')[1]))

        user = User(name=name, email=email, phone=phone, password=password, face_path=filename)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful.", "success")
        return redirect(url_for('login'))
    return render_template("registration.html")

# ----------------- POLLS & VOTING -----------------
@app.route('/polls')
@login_required
def polls():
    return render_template("poll.html", polls=Poll.query.all())

@app.route('/vote/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)

    if request.method == 'POST':
        selected_option = request.form['selected_option']
        otp_entered = request.form['otp']
        stored_otp = session.get('otp')

        if otp_entered != stored_otp:
            flash("Incorrect OTP. Please try again.", "danger")
            return redirect(url_for('vote', poll_id=poll_id))

        # ❗️Check if user has already voted on this poll
        existing_vote = Vote.query.filter_by(email=current_user.email, poll_id=poll_id).first()
        if existing_vote:
            flash("You have already voted on this poll.", "warning")
            return redirect(url_for('my_votes'))

        new_vote = Vote(email=current_user.email, poll_id=poll_id, selected_option=selected_option)
        db.session.add(new_vote)
        db.session.commit()
        flash("✅ Vote submitted successfully!", "success")
        return redirect(url_for('my_votes'))

    return render_template('voting.html', poll=poll)


@app.route('/myvotes')
@login_required
def my_votes():
    votes = Vote.query.filter_by(email=current_user.email).all()
    user_votes = [{'poll_title': Poll.query.get(v.poll_id).title, 'selected_option': v.selected_option} for v in votes]
    return render_template("my_votes.html", user_votes=user_votes)

@app.route('/results/<int:poll_id>')
@login_required
def results(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    votes = Vote.query.filter_by(poll_id=poll.id).all()

    # Count votes per option
    results = {}
    for option in poll.options:
        results[option] = sum(1 for v in votes if v.selected_option == option)

    # Get all polls for navigation
    all_polls = Poll.query.order_by(Poll.id.desc()).all()

    return render_template("results.html", poll=poll, results=results, all_polls=all_polls)



# ----------------- SETTINGS -----------------
@app.route('/settings')
@login_required
def settings():
    latest_poll = Poll.query.order_by(Poll.id.desc()).first()
    return render_template("setting.html", latest_poll=latest_poll)




@app.route('/manageprofile', methods=['GET', 'POST'])
@login_required
def manage_profile():
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.email = request.form['email']
        current_user.phone = request.form['phone']
        db.session.commit()
        flash("Profile updated!", "success")
    return render_template("manageprofile.html")

@app.route('/changepassword', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['currentPassword']
        new = request.form['newPassword']
        confirm = request.form['confirmPassword']
        if not bcrypt.check_password_hash(current_user.password, current):
            flash("Incorrect current password.", "danger")
        elif new != confirm:
            flash("New passwords do not match.", "warning")
        else:
            current_user.password = bcrypt.generate_password_hash(new).decode('utf-8')
            db.session.commit()
            flash("Password updated successfully!", "success")
            return redirect(url_for('settings'))
    return render_template("changepassword.html")

@app.route('/about')
def about():
    return render_template("aboutus.html")

# ----------------- ANONYMOUS VOTING -----------------
@app.route('/anon_vote/<int:poll_id>', methods=['GET', 'POST'])
def anon_vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    
    if request.method == 'POST':
        email = request.form['email']
        otp = request.form['otp']
        selected_option = request.form['selected_option']
        photo_data = request.form.get('photoData')

        if otp != session.get('otp'):
            flash("OTP verification failed.", "danger")
            return redirect(url_for('anon_vote', poll_id=poll_id))

        # Prevent duplicate vote
        existing_vote = Vote.query.filter_by(email=email, poll_id=poll_id).first()
        if existing_vote:
            flash("You have already voted on this poll.", "warning")
            return redirect(url_for('homepage'))

        # ✅ Save to static/faces/
        safe_email = re.sub(r'[^a-zA-Z0-9]', '_', email)
        filename = f"anon_{safe_email}.jpg"
        relative_path = f"faces/{filename}"  # what goes into DB and HTML
        full_path = os.path.join("static", relative_path)  # actual full path for saving



        os.makedirs(os.path.dirname(full_path), exist_ok=True)


        with open(full_path, "wb") as f:
            f.write(base64.b64decode(photo_data.split(',')[1]))

        if not AnonymousUser.query.filter_by(email=email).first():
            db.session.add(AnonymousUser(email=email, face_path=relative_path))  # 👈 save relative path

        db.session.add(Vote(poll_id=poll_id, email=email, selected_option=selected_option))
        db.session.commit()
        flash("✅ Vote submitted successfully!", "success")
        return redirect(url_for('results', poll_id=poll_id))

    return render_template("anon_voting.html", poll=poll)


@app.route('/delete_anon_voter/<int:anon_user_id>', methods=['POST'])
@login_required
def delete_anon_voter(anon_user_id):
    anon = AnonymousUser.query.get_or_404(anon_user_id)
    if anon.face_path:
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], anon.face_path)
        if os.path.exists(full_path):
            os.remove(full_path)
    db.session.delete(anon)
    db.session.commit()
    flash("Anonymous voter deleted.", "info")
    return redirect(url_for('manage_voters'))



# ----------------- ADMIN -----------------
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('homepage'))
    stats = {
        'users': User.query.count(),
        'anon_users': AnonymousUser.query.count(),  # Include anonymous user count
        'polls': Poll.query.count(),
        'votes': Vote.query.count()
    }
    return render_template("admin/admin.html", stats=stats)


@app.route('/make_admin_once')
def make_admin_once():
    user = User.query.filter_by(email='cihe22804@student.cihe.edu.au').first()
    if user:
        user.is_admin = True
        db.session.commit()
        return "✅ User promoted to admin."
    return "❌ User not found."


from flask import request, redirect, url_for, render_template
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
from app import app, db
from models import Poll

@app.route('/admin/add_poll', methods=['GET', 'POST'])
@login_required
def add_polls():
    if not current_user.is_admin:
        return redirect(url_for('homepage'))

    if request.method == 'POST':
        title = request.form.get('title')
        question = request.form.get('question')
        options = request.form.getlist('options[]')
        image = request.files.get('image')

        if not (title and question and options and image):
            return "Missing required fields", 400

        # Folder inside static
        relative_folder = 'faces/polls'  # stored in DB
        full_folder_path = os.path.join('static', relative_folder)  # avoid using UPLOAD_FOLDER here

        os.makedirs(full_folder_path, exist_ok=True)

        filename = secure_filename(image.filename)
        image.save(os.path.join(full_folder_path, filename))

        image_path = f'{relative_folder}/{filename}'  # for DB use

        new_poll = Poll(
            title=title,
            question=question,
            options=options,
            image=image_path
        )
        db.session.add(new_poll)
        db.session.commit()

        return redirect(url_for('admin'))

    return render_template("admin/add_polls.html")



@app.route('/admin/manage_votes')
@login_required
def manage_votes():
    if not current_user.is_admin:
        return redirect(url_for('homepage'))
    polls = Poll.query.all()
    data = [{
        'id': p.id,
        'title': p.title,
        'question': p.question,
        'total_votes': Vote.query.filter_by(poll_id=p.id).count()
    } for p in polls]
    return render_template("admin/manage_votes.html", polls=data)

@app.route('/admin/manage_voters')
@login_required
def manage_voters():
    if not current_user.is_admin:
        return redirect(url_for('homepage'))
    
    users = User.query.all()
    anon_users = AnonymousUser.query.all()  # This will get passed to your template
    
    return render_template('admin/manage_voters.html', users=users, anon_users=anon_users)



@app.route('/admin/delete_poll/<int:poll_id>', methods=['POST'])
@login_required
def delete_poll(poll_id):
    if not current_user.is_admin:
        return redirect(url_for('homepage'))
    Vote.query.filter_by(poll_id=poll_id).delete()
    db.session.delete(Poll.query.get_or_404(poll_id))
    db.session.commit()
    return redirect(url_for('manage_votes'))

@app.route('/admin/delete_voter/<int:user_id>', methods=['POST'])
@login_required
def delete_voter(user_id):
    if not current_user.is_admin:
        return redirect(url_for('homepage'))
    user = User.query.get_or_404(user_id)
    Vote.query.filter_by(email=user.email).delete()
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('manage_voters'))

@app.route('/admin/promote/<int:user_id>', methods=['POST'])
@login_required
def promote_admin(user_id):
    if not current_user.is_admin:
        return redirect(url_for('homepage'))
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    return redirect(url_for('manage_voters'))

@app.route('/admin/demote/<int:user_id>', methods=['POST'])
@login_required
def demote_admin(user_id):
    if not current_user.is_admin:
        return redirect(url_for('homepage'))
    user = User.query.get_or_404(user_id)
    user.is_admin = False
    db.session.commit()
    return redirect(url_for('manage_voters'))
