from flask_ckeditor import CKEditorField
from flask_wtf import FlaskForm
from wtforms import SubmitField, PasswordField, StringField, validators, EmailField, SelectField
from wtforms.fields.numeric import IntegerField
from wtforms.fields.simple import BooleanField, TextAreaField
from wtforms.validators import EqualTo


class Login(FlaskForm):
    email = EmailField('Email', validators=[validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')


class StudentRegistration(FlaskForm):
    email = EmailField('Email', validators=[validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
        validators.DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    confirm = BooleanField('Confirm', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')


class TechnicianRegistration(FlaskForm):
    first_name = StringField("First Name", validators=[validators.DataRequired()])
    last_name = StringField("First Name", validators=[validators.DataRequired()])
    email = EmailField('Email', validators=[validators.Email(), validators.DataRequired()])
    occupation_choices = [('Electrical', 'Electrical'), ('Plumbing', 'Plumbing'), ('Civil', 'Civil')]
    occupation = SelectField("Occupation", choices=occupation_choices, validators=[validators.DataRequired()])
    phone_number = StringField("Phone Number", validators=[
        validators.Regexp(r'^\+?27?\d{9}$', message="Invalid South African phone number")
    ])
    residing_area = SelectField('Residing City',
                                choices=[('Durban', 'Durban'), ('Pietermaritzburg', 'Pietermaritzburg')],
                                validators=[validators.DataRequired()])
    confirm = BooleanField('Confirm', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')


class ReportIssue(FlaskForm):
    campus = SelectField("Campus", validators=[validators.DataRequired()])
    block = SelectField("Block", validators=[validators.DataRequired()])
    location = StringField("Fault Location", validators=[validators.DataRequired()])
    issue_summary = StringField("Issue Summary", validators=[validators.DataRequired()])
    fault_type = SelectField("Fault type", validators=[validators.DataRequired()])
    confirm = BooleanField('Confirm', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')


class Verify(FlaskForm):
    OTP = IntegerField('OTP', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')


class ForgotPassword(FlaskForm):
    email = EmailField('Email', validators=[validators.Email(), validators.DataRequired()])
    submit = SubmitField('Submit')


class ResetPassword(FlaskForm):
    password = PasswordField('Password', validators=[validators.DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[
        validators.DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    confirm = BooleanField('Confirm', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')


class AssignTechnician(FlaskForm):
    technicians = SelectField("Available Technicians", validators=[validators.DataRequired()])
    confirm = BooleanField('Confirm', validators=[validators.DataRequired()])
    submit = SubmitField("Add technician")


class IssueResolvedForm(FlaskForm):
    editor_text = CKEditorField('Describe the solution', validators=[validators.DataRequired()])
    confirm = BooleanField('Confirm', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')

class Contact(FlaskForm):
    name = StringField("Name", validators=[validators.DataRequired()])
    email = EmailField('Email', validators=[validators.Email(), validators.DataRequired()])
    message = TextAreaField('Message', validators=[validators.DataRequired()])
    submit = SubmitField('Submit')
