from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from . import auth
from .. import db
from ..models import User
from ..email import send_email
from .forms import LoginForm, RegistrationForm, ChangePasswordForm,\
    PasswordResetRequestForm, PasswordResetForm, ChangeEmailForm


# 过滤未确认的账户，导向 /auth/unconfirmed 路由
@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()    # 更新已登录用户的访问时间
        if not current_user.confirmed \
                and request.endpoint[:5] != 'auth.'\
                and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


# 处理未确认的账户
@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('无效的账号或密码！')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已经退出登录状态！')
    return redirect(url_for('main.index'))


# 能发送确认邮件的注册路由
@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, '确认你的账户', 'auth/email/confirm', user=user, token=token)
        flash('一份确认邮件已经发往你的邮箱！')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


# 确认用户账户的路由
@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('你已经确认你的账号，谢谢！')
    else:
        flash('确认链接已经无效或过期。')
    return redirect(url_for('main.index'))


# 重新发送账户确认邮件
@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, '确认你的账户', 'auth/email/confirm', user=current_user, token=token)
    flash('一份确认邮件已经发往你的邮箱！')
    return redirect(url_for('main.index'))


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            logout_user()
            flash('你的密码已经更新,请重新登录')
            return redirect(url_for('auth.login'))
        else:
            flash('密码无效！')
    return render_template('auth/change_password.html', form=form)


@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.email, '重置你的密码',
                       'auth/email/reset_password',
                       user=user, token=token,
                       next=request.args.get('next'))
            flash('一封邮件已经发往你的邮箱，它将指导你如何重设密码')
            return redirect(url_for('auth.login'))
        flash('无效的账户！')
    return render_template('auth/reset_password.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('你的密码已经更新。')
            return redirect(url_for('auth.login'))
        else:
            flash('链接已过期或电子邮箱地址无效')
            # return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_email_change_token(new_email)
            send_email(new_email, '确认你的邮箱', 'auth/email/change_email', user=current_user, token=token)
            flash('一封邮件已经发送给你，它将指导你确认你的新邮箱。')
            return redirect(url_for('main.index'))
        else:
            flash('密码无效')
    return render_template('auth/change_password.html', form=form)


@auth.route('/change-email/<token>')
@login_required
def change_email(token):
    if current_user.change_email(token):
        flash('你的邮箱已经更新')
    else:
        flash('无效的请求')
    return redirect(url_for('main.index'))
