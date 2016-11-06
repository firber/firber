from flask import g, jsonify
from flask_httpauth import HTTPBasicAuth
from ..models import User, AnonymousUser
from . import api
from .errors import unauthorized, forbidden

auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(email_or_token, password):
    if email_or_token == '':
        g.current_user = AnonymousUser()  # 账户或令牌为空，认定为匿名用户
        return True
    if password == '':  # 密码为空，按照令牌的方式进行认证
        g.current_user = User.verify_auth_token(email_or_token)
        g.token_used = True # 用以区分是否通过令牌认证
        return g.current_user is not None
    user = User.query.filter_by(email=email_or_token).first() # 正常认证方式
    if not user:
        return False
    g.current_user = user # 将通过认证的用户保存在全局对象g中，以便视图函数的访问
    g.token_used = False  # 用以区分是否通过令牌认证
    return user.verify_password(password)


@auth.error_handler
def auth_error():
    return unauthorized('Invalid credentials')


# 保护路由，进行认证确认，并拒绝没有确认账户的用户
@api.before_request
@auth.login_required
def before_request():
    if not g.current_user.is_anonymous and \
            not g.current_user.confirmed:
        return forbidden('Unconfirmed account')


# 生成认证令牌
@api.route('/token')
def get_token():
    if g.current_user.is_anonymous or g.token_used: # 拒绝匿名用户，并防止使用旧令牌申请新令牌
        return unauthorized('Invalid credentials')
    return jsonify({'token': g.current_user.generate_auth_token(
        expiration=3600), 'expiration': 3600})