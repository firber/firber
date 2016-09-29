from flask_wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired


class NameForm(Form):
    name = StringField('你的姓名是什么？', validators=[DataRequired()])
    submit = SubmitField('提交')