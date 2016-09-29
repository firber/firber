from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(Form):
    email = StringField('电子邮件', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('密码', validators=[DataRequired()])
    remember_me = BooleanField('记住我')
    submit = SubmitField('登录')


class RegistrationForm(Form):
    email = StringField('电子邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('用户名称', validators=[DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, '用户名称应只包含字母、数字、下划线和点号')])
    password = PasswordField('密码', validators=[DataRequired(), EqualTo('password2', message='密码必须前后一致')])
    password2 = PasswordField('确认密码', validators=[DataRequired()])

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('电子邮件已经注册。')

    def validate_usernmae(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('用户名称已经使用！')

