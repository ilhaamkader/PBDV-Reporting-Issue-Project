import os
import string

import requests
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_mail import Mail, Message
from random import *
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor

from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import desc

from flask import session
import re
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash
import forms

app = Flask(__name__)

app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = os.environ.get('MAINTAINENCE_EMAIL')
app.config["MAIL_PASSWORD"] = os.environ.get('MAINTAINENCE_EMAIL_PASS')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


def get_otp() -> int:
    otp = randint(000000, 999999)
    return otp


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_STRING')
db.init_app(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
boostrap = Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)
ckeditor = CKEditor(app)


class Role(db.Model):
    Role_ID = db.Column(db.Integer, primary_key=True)
    Role_Name = db.Column(db.String(50), nullable=False)
    user = db.relationship('User', backref='role')


class User(UserMixin, db.Model):
    User_ID = db.Column(db.Integer, primary_key=True)
    Role_ID = db.Column(db.Integer, db.ForeignKey('role.Role_ID'), nullable=False)
    students = db.relationship('Student', backref='user', uselist=False)
    admins = db.relationship('Admin', backref='user', uselist=False)
    technicians = db.relationship('Technician', backref='user', uselist=False)

    def get_id(self):
        return str(self.User_ID)


class Student(db.Model):
    Student_ID = db.Column(db.Integer, primary_key=True)
    User_ID = db.Column(db.Integer, db.ForeignKey('user.User_ID'), nullable=False, unique=True)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    Password = db.Column(db.String(100), nullable=False)

    # Define other student fields here


class Admin(db.Model):
    Admin_ID = db.Column(db.Integer, primary_key=True)
    User_ID = db.Column(db.Integer, db.ForeignKey('user.User_ID'), nullable=False, unique=True)
    First_name = db.Column(db.String(50), nullable=False)
    Last_name = db.Column(db.String(50), nullable=False)
    Password = db.Column(db.String(100), nullable=False)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    technicians = db.relationship('Technician', backref='admin')

    # Define other admin fields here




class Technician(db.Model):
    Technician_ID = db.Column(db.Integer, primary_key=True)
    User_ID = db.Column(db.Integer, db.ForeignKey('user.User_ID'), nullable=False, unique=True)
    Admin_ID = db.Column(db.Integer, db.ForeignKey('admin.Admin_ID'), nullable=False)
    First_name = db.Column(db.String(50), nullable=False)
    Last_name = db.Column(db.String(50), nullable=False)
    Password = db.Column(db.String(50), nullable=False)
    Residing_area = db.Column(db.String(70), nullable=False)
    Phone_number = db.Column(db.String(20), nullable=False)
    Email = db.Column(db.String(100), nullable=False, unique=True)
    Job_description = db.Column(db.String(100), nullable=False)
    faults = db.relationship('Fault', backref='Technician')
    # Define other technician fields here


class Campus(db.Model):
    Campus_ID = db.Column(db.Integer, primary_key=True)
    Campus_location = db.Column(db.String(100), nullable=False)
    Campus_name = db.Column(db.String(100), nullable=False)
    Blocks = db.Column(db.JSON, nullable=False, default=[])  # Storing block information in JSON format
    Campus_map_url = db.Column(db.String(200))
    faults = db.relationship('Fault', backref='campus')


class Fault(db.Model):
    Fault_ID = db.Column(db.Integer, primary_key=True)
    Campus_ID = db.Column(db.Integer, db.ForeignKey('campus.Campus_ID'), nullable=False)
    Block = db.Column(db.String(50), nullable=False)  # Storing the block as a string
    Location = db.Column(db.String(100))
    Description = db.Column(db.Text, nullable=False)
    Fault_Type = db.Column(db.String(50), nullable=False)
    Date_submitted = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc).date)
    Upvotes = db.Column(db.JSON, nullable=False, default=[])  # Using JSON type for Upvotes
    Status = db.Column(db.String(50), nullable=False, default='In Progress')
    Technician_ID = db.Column(db.Integer, db.ForeignKey('technician.Technician_ID'), nullable=True)
    fault_log = db.Column(db.String(100), nullable=True)
    Date_completed = db.Column(db.DateTime, nullable=True)


@login_manager.user_loader
def load_user(User_ID):
    return db.session.get(User, User_ID)


def get_username_from_email(email):
    # Split the email address at the "@" symbol
    parts = email.split("@")
    # Return the part before the "@" symbol
    return parts[0]


def calculate_priority(upvotes, issue_date):
    issue_date = datetime.strptime(str(issue_date), "%Y-%m-%d %H:%M:%S")
    current_date = datetime.now(timezone.utc)
    days_difference = (current_date.date() - issue_date.date()).days
    priority_score = 0

    if days_difference < 5:
        priority_score += 1
    elif days_difference < 10:
        priority_score += 2
    else:
        priority_score += 3

    if len(upvotes) > 10:
        priority_score += 3
    elif len(upvotes) > 5:
        priority_score += 2

    if priority_score <= 2:
        priority = 'low'
    elif priority_score <= 4:
        priority = 'medium'
    else:
        priority = 'high'

    return priority


def generate_password():
    # Specify counts for letters, numbers, and symbols
    Letter_Count = 8  # Example: 8 letters
    Number_Count = 4  # Example: 4 numbers
    Symbol_Count = 2  # Example: 2 symbols

    Password_List = []
    # Generate letters
    for L in range(Letter_Count):
        Password_List.append(choice(string.ascii_letters))
    # Generate numbers
    for N in range(Number_Count):
        Password_List.append(choice(string.digits))
    # Generate symbols
    for S in range(Symbol_Count):
        Password_List.append(choice(string.punctuation))

    # Shuffle the password list
    shuffle(Password_List)

    # Concatenate the characters to form the password
    Randomised_String = ''.join(Password_List)
    return Randomised_String


def get_email_body(first_name, last_name, email, phone_number, residence, skill, password):
    body = f"Below are your details:\n\nFirst Name: {first_name}\nLast Name: {last_name}\nEmail Address: {email}\nPhone Number: {phone_number}\nPlace of Residence: {residence}\nSkill: {skill}\nPassword: {password}"
    return body


def get_weather_forecast():
    api_key = os.environ.get('WEATHER_API_KEY')
    ENDPOINT = "https://api.openweathermap.org/data/2.5/forecast"

    weather_params = {
        "lon": 31.021839,
        "lat": -29.858681,
        "appid": api_key,
        "units": "metric",  # Request temperature in Celsius
        "cnt": 7 * 8,  # Request 8 forecasts for 7 days to get data for each day
    }

    response = requests.get(url=ENDPOINT, params=weather_params)
    response.raise_for_status()
    weather_data = response.json()

    weather_forecast = {}

    for forecast in weather_data['list']:
        timestamp = forecast['dt']
        date = datetime.utcfromtimestamp(timestamp)

        day_of_week = date.weekday()
        if day_of_week not in weather_forecast:
            weather_forecast[day_of_week] = (date.strftime("%A"), forecast['weather'][0]['description'].capitalize())

    return weather_forecast


@app.route('/')
def display_home():
    return render_template('home.html')


@app.route('/login/<user>', methods=['GET', 'POST'])
def display_login(user):
    form = forms.Login()
    if current_user.is_active:
        flash('User already logged in!')
    if user == '1':
        # Student login
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            student = db.session.execute(db.select(Student).where(Student.Email == email)).scalar()
            if student:
                if check_password_hash(password=password, pwhash=student.Password):
                    logged_in_user = db.session.execute(db.select(User).where(User.User_ID == student.User_ID)).scalar()
                    login_user(logged_in_user)
                    return redirect(url_for('display_student_dashboard'))
                    # this log in a user at this point
                else:
                    flash('incorrect password')
                    return redirect(url_for('display_login', user=1, role=2))
            else:
                flash('User does not exist')
                return redirect(url_for('display_login', user=1, role=2))
        return render_template('login.html', form=form, role=2)
    elif user == '2':
        # this will be the Tech login action
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            technician = db.session.execute(db.select(Technician).where(Technician.Email == email)).scalar()
            if technician:
                if check_password_hash(password=password, pwhash=technician.Password):
                    logged_in_user = db.session.execute(
                        db.select(User).where(User.User_ID == technician.User_ID)).scalar()
                    login_user(logged_in_user)
                    return redirect(url_for('display_technician_dashboard'))
                else:
                    flash('incorrect password')
                    return redirect(url_for('display_login', user=2, role=2))
            else:
                flash('User does not exist')
                return redirect(url_for('display_login', user='2', role=3))
        return render_template('login.html', form=form, role=3)
    elif user == '3':
        # Admin login
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            print(5)
            admin = db.session.execute(db.select(Admin).where(Admin.Email == email)).scalar()
            if admin:
                if check_password_hash(password=password
                        , pwhash=admin.Password):
                    logged_in_user = db.session.execute(db.select(User).where(User.User_ID == admin.User_ID)).scalar()
                    login_user(logged_in_user)
                    print(current_user.User_ID)
                    return redirect(url_for('display_admin_dashboard'))
                    # this log in a user at this point
                else:
                    flash('incorrect password')
                    return redirect(url_for('display_login', user=3, role=2))
            else:
                flash('User does not exist')
                return redirect(url_for('display_login', user='3', role=1))
        return render_template('login.html', form=form, role=1)


@app.route('/register', methods=['GET', 'POST'])
def display_registration():
    form = forms.StudentRegistration()

    if request.method == 'POST':
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            user_exists = db.session.execute(db.select(Student).where(Student.Email == email)).scalar()
            if user_exists:
                flash('This User exists already!')
                return redirect(url_for('display_login', user=1))

            if validate_student_email(email):
                otp = get_otp()
                session['otp'] = otp
                session['email'] = email
                session['password'] = password
                if is_strong_password(password):
                    msg = Message(subject='OTP', sender='dutmaintenance@gmail.com', recipients=[email])
                    msg.body = "Use this One-Time-Pin to verify your email: \n" + str(otp)
                    mail.send(msg)

                    return redirect(url_for('verify'))
                else:
                    flash(
                        "Password invalid.Must be >= 8 characters,1 uppercase & lowercase,1 digit,1 special character",
                        "error")
                    return render_template('register.html', form=form)
            else:
                flash("Email not valid", "error")

        if 'email' in session and 'password' in session:
            form.email.data = session['email']
            form.password.data = session['password']

    return render_template('register.html', form=form)


def is_strong_password(password):
    # Check if password meets the following criteria:
    # - At least 8 characters long
    # - Contains at least one uppercase letter
    # - Contains at least one lowercase letter
    # - Contains at least one digit
    # - Contains at least one special character (e.g., !@#$%^&*)

    if len(password) < 8:
        return False

    if not re.search(r'[A-Z]', password):
        return False

    if not re.search(r'[a-z]', password):
        return False

    if not re.search(r'\d', password):
        return False

    if not re.search(r'[!@#$%^&*]', password):
        return False

    return True


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    verify_form = forms.Verify()

    if verify_form.validate_on_submit():
        user_otp = verify_form.OTP.data
        otp = session.pop('otp')
        if otp == int(user_otp):
            # Retrieve form data from session
            email = session.get('email')
            password = session.get('password')
            user_record = User(Role_ID=2)
            db.session.add(user_record)
            db.session.commit()
            last_inserted_user = User.query.order_by(desc(User.User_ID)).first()
            student_record = Student(User_ID=last_inserted_user.User_ID,
                                     Email=email,
                                     Password=generate_password_hash(password, salt_length=8))
            db.session.add(student_record)
            db.session.commit()
            # Now you can use the email and password to complete the registration process
            flash('Email verified', 'success')
            return redirect(url_for('display_login', user=1))  # Redirect to the home page after verification
        else:
            flash('Incorrect OTP, please try again', 'error')
            return redirect(url_for('verify'))  # Redirect back to the verification page

    return render_template('verify.html', form=verify_form)


def validate_student_email(email):
    if not re.match(r'^\d{8}@dut4life\.ac\.za$', email):
        return False
    year = int(email[:2])
    current_year = datetime.now().year % 100
    if year > current_year:
        return False
    return True


def get_campus_info():
    campus = db.session.execute(db.select(Campus)).scalars()
    return campus


@app.route('/register_technician', methods=['GET', 'POST'])
@login_required
def display_technician_registration():
    form = forms.TechnicianRegistration()
    if current_user.Role_ID != 1:
        return "ACCESS DENIED"

    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        phone_number = form.phone_number.data
        email = form.email.data
        job_desc = form.occupation.data
        residing_area = form.residing_area.data
        user = User(Role_ID=3)
        db.session.add(user)
        db.session.commit()
        password = generate_password()
        last_inserted_user = User.query.order_by(desc(User.User_ID)).first()
        admin_record = db.session.execute(db.select(Admin).where(Admin.User_ID == current_user.User_ID)).scalar()
        technician = Technician(First_name=first_name,
                                Last_name=last_name,
                                Phone_number=phone_number,
                                Email=email,
                                Password=generate_password_hash(password, salt_length=8),
                                Residing_area=residing_area,
                                Job_description=job_desc,
                                Admin_ID=admin_record.Admin_ID,
                                User_ID=last_inserted_user.User_ID
                                )
        db.session.add(technician)
        db.session.commit()
        msg = Message(subject="Congratulations, you are now a registered DUT technician",
                      sender='dutmaintenance@gmail.com', recipients=[email])
        msg.body = get_email_body(first_name=first_name, last_name=last_name, email=email, phone_number=phone_number,
                                  residence=residing_area, skill=job_desc, password=password)
        mail.send(msg)
        flash('Registration Complete')
        return redirect(url_for('display_admin_dashboard'))
    return render_template('register.html', form=form)


@app.route('/contact', methods=['GET', 'POST'])
def display_contact():
    form = forms.Contact()

    if request.method == 'POST':
        if form.validate_on_submit():
            name = form.name.data
            email = form.email.data
            message = form.message.data
            msg = Message(subject='New Contact Form Submission', sender=email, recipients=['dutmaintenance@gmail.com'])
            msg.body = f"You have received a new message from {name} ({email}):\n\n{message}"
            mail.send(msg)

            flash('Your message has been sent successfully!', 'success')
            return redirect(url_for('display_contact'))

        else:
            flash('Please fill in all the required fields.', 'error')

    return render_template('contact.html', form=form)


@app.route('/student_dashboard')
@login_required
def display_student_dashboard():
    if current_user.Role_ID != 2:
        flash('Route access not allowed!')
        return redirect(url_for('display_home'))
    weather_forecast = get_weather_forecast()
    student = db.session.execute(db.select(Student).where(Student.User_ID == current_user.User_ID)).scalar()
    student_id = student.Student_ID
    all_faults = db.session.execute(db.select(Fault)).scalars()
    upvoted_faults = []
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    for fault in all_faults:
        if student_id in fault.Upvotes:
            upvoted_faults.append(fault)

    student_info = {"username": get_username_from_email(student.Email),
                    "email": student.Email}
    return render_template('student_dashboard.html', faults=upvoted_faults, student_info=student_info,
                           campus_names=campus_names, weather_forecast=weather_forecast)


@app.route('/technician_dashboard')
@login_required
def display_technician_dashboard():
    if current_user.Role_ID != 3:
        flash('NOT ALLOWED!')
        return redirect(url_for('display_home'))
    weather_forecast = get_weather_forecast()
    technician = db.session.execute(db.select(Technician).where(Technician.User_ID == current_user.User_ID)).scalar()
    technician_id = technician.Technician_ID
    tech_info = {"username": f'{technician.First_name} {technician.Last_name}',
                 "email": technician.Email}
    all_faults = db.session.execute(db.select(Fault)).scalars()
    all_issues = [issue for issue in all_faults]
    for i in range(0, len(all_issues)):
        all_issues[i].Priority = calculate_priority(upvotes=all_issues[i].Upvotes,
                                                    issue_date=all_issues[i].Date_submitted)
    upvoted_faults = []
    for fault in all_issues:
        if technician_id == fault.Technician_ID:
            upvoted_faults.append(fault)
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    return render_template('tech_dashboard.html', faults=upvoted_faults, tech_info=tech_info, all_faults=all_faults,
                           campus_names=campus_names, weather_forecast=weather_forecast)


@app.route('/admin_dashboard')
@login_required
def display_admin_dashboard():
    admin = db.session.execute(db.select(Admin).where(Admin.User_ID == current_user.User_ID)).scalar()
    technicians = db.session.execute(db.select(Technician)).scalars()
    all_issues = db.session.execute(db.select(Fault)).scalars()
    all_issues = [issue for issue in all_issues]
    for i in range(0, len(all_issues)):
        all_issues[i].Priority = calculate_priority(upvotes=all_issues[i].Upvotes,
                                                    issue_date=all_issues[i].Date_submitted)
    admin_info = {"username": get_username_from_email(admin.Email),
                  "email": admin.Email}
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    all_admins = db.session.execute(db.select(Admin)).scalars()
    all_admins_dict = {admin.User_ID: get_username_from_email(admin.Email) for admin in all_admins}
    weather_forecast = get_weather_forecast()
    print(all_admins_dict)
    return render_template('admin_dashboard.html', campus_names=campus_names, faults=all_issues,
                           technicians=technicians, admin_info=admin_info, all_admins_dict=all_admins_dict,weather_forecast=weather_forecast)


@app.route('/view_pending/<fault_id>', methods=['GET', 'POST'])
@login_required
def display_pending_fault(fault_id):
    if current_user.Role_ID != 1:
        flash('Not allowed!')
        return redirect(url_for('display_home'))
    form = forms.AssignTechnician()
    if request.method == 'POST':
        fault = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
        fault.Technician_ID = form.technicians.data
        fault.Status = 'In Progress'
        db.session.commit()
        flash('Fault updated successfully!')
        return redirect(url_for('display_admin_dashboard'))
    fault = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
    technicians = db.session.execute(
        db.select(Technician).where(Technician.Job_description == fault.Fault_Type)).scalars()
    form.technicians.choices = [(t.Technician_ID, f'{t.First_name} {t.Last_name}:{t.Email}') for t in technicians]
    fault.Priority = calculate_priority(upvotes=fault.Upvotes, issue_date=fault.Date_submitted)
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    if fault:
        return render_template('pending_issue.html', fault=fault, campus_names=campus_names, form=form)
    else:
        flash('Invalid Fault!')
        return render_template('display_home')


@app.route('/delete_post/<fault_id>', methods=['GET', 'POST'])
@login_required
def delete_fault(fault_id):
    if current_user.Role_ID != 1:
        flash('NOT ALLOWED!', 'error')
        return redirect(url_for('display_home'))
    if request.method == "GET":
        fault = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
        db.session.delete(fault)
        db.session.commit()
        flash('Removal successful')
        return redirect(url_for('display_admin_dashboard'))
    else:
        return redirect(url_for('display_admin_dashboard'))


@app.route('/view_active/<fault_id>')
@login_required
def display_active_fault_admin(fault_id):
    if current_user.Role_ID != 1:
        flash('NOT ALLOWED')
        return redirect(url_for('display_home'))
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    fault = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
    fault.Priority = calculate_priority(upvotes=fault.Upvotes, issue_date=fault.Date_submitted)
    technician = db.session.execute(
        db.select(Technician).where(Technician.Technician_ID == fault.Technician_ID)).scalar()
    return render_template('admin_active_fault.html', fault=fault, technician=technician, campus_names=campus_names)


@app.route('/view_completed/<fault_id>')
@login_required
def display_completed_fault_admin(fault_id):
    if current_user.Role_ID != 1:
        flash('NOT ALLOWED')
        return redirect(url_for('display_home'))
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    fault = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
    technician = db.session.execute(
        db.select(Technician).where(Technician.Technician_ID == fault.Technician_ID)).scalar()
    return render_template('admin_completed_fault.html', fault=fault, technician=technician, campus_names=campus_names)


@app.route('/view_active_tech_faults/<fault_id>', methods=['GET', 'POST'])
@login_required
def display_active_tech_faults(fault_id):
    if current_user.Role_ID != 3:
        flash('NOT ALLOWED!')
        return redirect(url_for('display_home'))
    form = forms.IssueResolvedForm()
    print(form.validate_on_submit())
    if form.validate_on_submit():
        try:
            fault = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
            fault.fault_log = form.editor_text.data
            fault.Date_completed = datetime.now(timezone.utc)
            fault.Status = 'Completed'
            db.session.commit()
            flash('Successful!')
            return redirect(url_for('display_technician_dashboard'))
        except:
            flash('An error occurred')
            return redirect(url_for('display_home'))

    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    fault = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
    return render_template('issue_descriptions.html', form=form, fault=fault, campus_names=campus_names)


@app.route('/view_completed_tech_fault/<fault_id>', methods=['GET'])
@login_required
def display_completed_tech_fault(fault_id):
    if current_user.Role_ID != 3:
        flash('NOT ALLOWED!')
        return redirect(url_for('display_home'))

    fault = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    return render_template('completed_tech_fault.html', fault=fault, campus_names=campus_names)


@app.route('/view_filter/<filter>/<fault_id>', methods=['GET'])
@login_required
def display_view_filter(filter,fault_id):
    if current_user.Role_ID != 3:
        flash('NOT ALLOWED!')
        return redirect(url_for('display_home'))
    filters = ['campus', 'block', 'fault_type']
    if filter not in filters:
        flash('filter doesnt exist')
        return redirect(url_for('display_technician_dashboard'))
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    faults = ''
    fault = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
    if not fault:
        flash('Fault does not exist!')
        return redirect(url_for('display_tech_dashboard'))

    if filter == filters[0]:
        faults = db.session.execute(db.select(Fault).where(Fault.Campus_ID == fault.Campus_ID)).scalars()
    elif filter == filters[1]:
        faults = db.session.execute(db.select(Fault).where(Fault.Campus_ID == fault.Campus_ID , Fault.Block == fault.Block)).scalars()
    elif filter == filters[2]:
        faults = db.session.execute(db.select(Fault).where(Fault.Campus_ID == fault.Campus_ID , Fault.Block == fault.Block , Fault.Fault_Type == fault.Fault_Type)).scalars()
    return render_template('view_filter.html',faults=faults,campus_names=campus_names)


@app.route('/viewIssue', methods=['GET'])
def display_issue():
    issues = db.session.execute(db.select(Fault)).scalars()

    def get_upvotes_length(obj):
        return len(obj.Upvotes)

    # Sort the list of objects based on the lengths of their 'upvotes' field
    sorted_list = sorted(issues, key=get_upvotes_length, reverse=True)
    for i in range(0, len(sorted_list)):
        sorted_list[i].Priority = calculate_priority(upvotes=sorted_list[i].Upvotes,
                                                     issue_date=sorted_list[i].Date_submitted)
    campus_names = {x.Campus_ID: x.Campus_name for x in get_campus_info()}
    return render_template('view_issue.html', faults=sorted_list, campus_names=campus_names)


@app.route('/upvote_issue/<fault_id>', methods=['GET', 'POST'])
@login_required
def upvote_issue(fault_id):
    if current_user.Role_ID != 2:
        flash('Only a student is allowed to escalate issues!')
        return redirect(url_for('display_home'))
    print(1)

    try:
        # Fetch the issue record using .first() for single result
        issue_record = db.session.execute(db.select(Fault).where(Fault.Fault_ID == fault_id)).scalar()
        if not issue_record:
            print(2)
            flash('Fault record does not exist')
            return redirect(url_for('display_home'))
        student = db.session.execute(db.select(Student).where(Student.User_ID == current_user.User_ID)).scalar()
        student_id = student.Student_ID
        print(3)
        if student_id in issue_record.Upvotes:
            flash('Cannot upvote twice!')
            return redirect(url_for('display_home'))

        print(4)
        # Ensure Upvotes is mutable (list) within JSON
        if not issue_record.Upvotes:
            issue_record.Upvotes = []
        new_votes = issue_record.Upvotes.copy()  # Avoid modifying original data
        new_votes.append(student_id)

        # Update using jsonb_set (adjust for your database)
        issue_record.Upvotes = new_votes
        db.session.commit()
        flash('Successfully escalated!')
    except Exception as e:
        print(f"An error occurred: {e}")
        flash('An error occurred while upvoting')
        return redirect(url_for('display_home'))

    return redirect(url_for('display_home'))


@app.route('/addIssue', methods=['GET', 'POST'])
@login_required
def display_add_issue():
    if current_user.Role_ID != 2:
        flash('Action not allowed!')
        return redirect(url_for('display_home'))
    form = forms.ReportIssue()
    campuses = [campus.Campus_name for campus in get_campus_info()]
    blocks = {campus.Campus_name: campus.Blocks for campus in get_campus_info()}
    form.campus.choices = [(campus, campus) for campus in campuses]
    form.block.choices = [(block, block) for block in blocks[campuses[0]]]
    campus_img_dict = {campus.Campus_name: campus.Campus_map_url for campus in get_campus_info()}
    form.fault_type.choices = [("Electrical", "Electrical"), ("Plumbing", "Plumbing"), ("Civil", "Civil")]
    student = db.session.execute(db.select(Student).where(Student.User_ID == current_user.User_ID)).scalar()
    student_id = student.Student_ID
    if request.method == 'POST':
        print(2)
        fault_entry = Fault(Campus_ID=(
            db.session.execute(db.select(Campus).where(Campus.Campus_name == form.campus.data)).scalar()).Campus_ID,
                            Block=form.block.data,
                            Location=form.location.data,
                            Fault_Type=form.fault_type.data,
                            Upvotes=[student_id],
                            Status="Pending",
                            Description=form.issue_summary.data)

        db.session.add(fault_entry)
        db.session.commit()
        return redirect(url_for('display_home'))

    return render_template('add_issue.html', form=form, blocks=blocks, campus_img_dict=campus_img_dict)


@app.route('/forgot-password/<role>', methods=['GET', 'POST'])
def forgot_password(role):
    form = forms.ForgotPassword()
    if request.method == 'POST':
        email = request.form.get('email')
        # Check if email exists in the database (you may need to query your database here)
        if role == '1':
            user = db.session.execute(db.select(Admin).where(Admin.Email == email)).scalar()
        elif role == '2':
            user = db.session.execute(db.select(Student).where(Student.Email == email)).scalar()
        elif role == '3':
            user = db.session.execute(db.select(Technician).where(Technician.Email == email)).scalar()
        else:
            flash('404,route does not exist', 'error')
            return redirect(url_for('forgot_password', role=role))

        if user:
            otp = get_otp()
            # Store OTP and email in session
            session['reset_password_email'] = email
            session['reset_password_otp'] = otp
            session['user_id'] = user.User_ID
            # Send OTP to user's email
            msg = Message(subject='Password Reset OTP', sender='dutmaintenance@gmail.com', recipients=[email])
            msg.body = f'Your OTP for password reset is: {otp}'
            mail.send(msg)
            # Redirect to OTP verification page
            return redirect(url_for('verify_otp'))
        else:
            flash('User does not exist!', 'error')
            return redirect(url_for('forgot_password', role=role))
    return render_template('forgot_password.html', form=form, role=role)


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    form = forms.Verify()
    if request.method == 'POST':
        if form.validate_on_submit():
            entered_otp = int(form.OTP.data)
            if entered_otp == session.get('reset_password_otp'):
                # OTP verification successful, allow user to reset password
                return redirect(url_for('reset_password'))
            else:
                flash('Invalid OTP. Please try again.', 'error')
    return render_template('verify_otp.html', form=form)


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    form = forms.ResetPassword()
    if request.method == 'POST':
        # Reset password logic (you may need to update your database with the new password)
        # Clear session after password reset
        password = form.password.data
        confirm_password = form.confirm_password.data
        print(password + " " + confirm_password)

        if is_strong_password(password):
            if password != confirm_password:
                flash('Passwords must match!')
                return redirect(url_for('reset_password'))

            email = session.pop('reset_password_email')
            user_id = session.pop('user_id')
            user = db.session.execute(db.select(User).where(User.User_ID == user_id)).scalar()
            role_id = user.Role_ID
            if role_id == 1:
                user = db.session.execute(db.select(Admin).where(Admin.Email == email)).scalar()
            elif role_id == 2:
                user = db.session.execute(db.select(Student).where(Student.Email == email)).scalar()
            elif role_id == 3:
                user = db.session.execute(db.select(Technician).where(Technician.Email == email)).scalar()
            user.Password = generate_password_hash(password, salt_length=8)
            db.session.commit()
            session.pop('reset_password_otp')
            flash('Password reset successful. You can now login with your new password.', 'success')
            return redirect(url_for('display_home'))
        else:
            flash("Password invalid.Must be >= 8 characters,1 uppercase & lowercase,1 digit,1 special character",
                  "error")

    return render_template('reset_password.html', form=form)


@app.route('/login_redirect')
def do_redirect():
    return redirect(url_for('display_login', user=1))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('display_home'))


login_manager.login_view = "do_redirect"
login_manager.login_message = u"Please login to complete this action"
login_manager.login_message_category = "info"

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True)
