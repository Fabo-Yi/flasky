# coding=utf-8
import hashlib
from datetime import datetime

import bleach
from flask import current_app, url_for
from flask_login import UserMixin, AnonymousUserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from markdown import markdown
from werkzeug.security import generate_password_hash, check_password_hash

from app.exceptions import ValidationError
from . import db, login_manager


class TimestampMixin(object):
    # created_at = Column(DateTime, default=lambda: timeutils.utcnow()+timedelta(hours=8))
    # updated_at = Column(DateTime, onupdate=lambda: timeutils.utcnow()+timedelta(hours=8))
    created_at = db.Column(DateTime, default=lambda: datetime.now())
    updated_at = db.Column(DateTime, onupdate=lambda: datetime.now())


class SoftDeleteMixin(object):
    deleted_at = db.Column(DateTime)
    deleted = db.Column(Integer, default=0)

    # def soft_delete(self, session):
    #     """Mark this object as deleted."""
    #     self.deleted = self.id
    #     self.deleted_at = datetime.now()
    #     self.save(session=session)


class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE],
            'Moderator': [Permission.FOLLOW, Permission.COMMENT,
                          Permission.WRITE, Permission.MODERATE],
            'Administrator': [Permission.FOLLOW, Permission.COMMENT,
                              Permission.WRITE, Permission.MODERATE,
                              Permission.ADMIN],
        }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm

    def __repr__(self):
        return '<Role %r>' % self.name


class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash()
        self.follow(self)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id}).decode('utf-8')

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id}).decode('utf-8')

    @staticmethod
    def reset_password(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps(
            {'change_email': self.id, 'new_email': new_email}).decode('utf-8')

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.avatar_hash = self.gravatar_hash()
        db.session.add(self)
        return True

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()

    def gravatar(self, size=100, default='identicon', rating='g'):
        url = 'https://secure.gravatar.com/avatar'
        hash = self.avatar_hash or self.gravatar_hash()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        if user.id is None:
            return False
        return self.followed.filter_by(
            followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        if user.id is None:
            return False
        return self.followers.filter_by(
            follower_id=user.id).first() is not None

    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id == Post.author_id) \
            .filter(Follow.follower_id == self.id)

    def to_json(self):
        json_user = {
            'url': url_for('api.get_user', id=self.id),
            'username': self.username,
            'member_since': self.member_since,
            'last_seen': self.last_seen,
            'posts_url': url_for('api.get_user_posts', id=self.id),
            'followed_posts_url': url_for('api.get_user_followed_posts',
                                          id=self.id),
            'post_count': self.posts.count()
        }
        return json_user

    def generate_auth_token(self, expiration):
        s = Serializer(current_app.config['SECRET_KEY'],
                       expires_in=expiration)
        return s.dumps({'id': self.id}).decode('utf-8')

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])

    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = db.relationship('Comment', backref='post', lazy='dynamic')

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

    def to_json(self):
        json_post = {
            'url': url_for('api.get_post', id=self.id),
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp,
            'author_url': url_for('api.get_user', id=self.author_id),
            'comments_url': url_for('api.get_post_comments', id=self.id),
            'comment_count': self.comments.count()
        }
        return json_post

    @staticmethod
    def from_json(json_post):
        body = json_post.get('body')
        if body is None or body == '':
            raise ValidationError('post does not have a body')
        return Post(body=body)


db.event.listen(Post.body, 'set', Post.on_changed_body)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
                        'strong']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

    def to_json(self):
        json_comment = {
            'url': url_for('api.get_comment', id=self.id),
            'post_url': url_for('api.get_post', id=self.post_id),
            'body': self.body,
            'body_html': self.body_html,
            'timestamp': self.timestamp,
            'author_url': url_for('api.get_user', id=self.author_id),
        }
        return json_comment

    @staticmethod
    def from_json(json_comment):
        body = json_comment.get('body')
        if body is None or body == '':
            raise ValidationError('comment does not have a body')
        return Comment(body=body)


db.event.listen(Comment.body, 'set', Comment.on_changed_body)


class AtomicTaskParam(db.Model, TimestampMixin, SoftDeleteMixin):
    """Represents ."""
    __tablename__ = 'atomic_task_params'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    key = db.Column(db.String(255))
    value = db.Column(db.String(255))
    atomic_task_id = db.Column(db.Integer, db.ForeignKey('atomic_tasks.id'))

    def __repr__(self):
        return '{"id": %s, "key": %s, "value": %s}' % (self.id, self.key, self.value)


class AtomicTask(db.Model, TimestampMixin, SoftDeleteMixin):
    """Represents ."""
    __tablename__ = 'atomic_tasks'
    # __table_args__ = (schema.UniqueConstraint('name'),)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    task_type = db.Column(db.Integer, db.ForeignKey('atomic_task_types.id'))
    icon = db.Column(db.String(255))
    type = db.Column(db.Enum('shell', 'playbook', 'python', name='cmd_types'),
                     nullable=False, server_default='shell')
    content = db.Column(db.Text)
    description = db.Column(db.String(255))

    plan_start = db.Column(db.BigInteger)
    plan_end = db.Column(db.BigInteger)
    key_task_flag = db.Column(db.Boolean, default=False)

    operator = db.Column(db.BigInteger)
    audit_person = db.Column(db.BigInteger)

    param = db.relationship(AtomicTaskParam, backref=db.backref('atomic_tasks'))

    def __repr__(self):
        return '{"id": %s, "name": %s, "task_type": %s, "icon": %s, "type": %s, "content": %s,' \
               ' "description": %s}' % (self.id, self.name, self.task_type,
                                        self.icon, self.type, self.content, self.description)


class AtomicTaskType(db.Model, TimestampMixin, SoftDeleteMixin):
    """Represents ."""
    __tablename__ = 'atomic_task_types'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255))

    tasks = db.relationship(AtomicTask, backref="atomic_task_types")

    def __repr__(self):
        return '{"id": %s, "name": %s}' % (self.id, self.name)


class TaskOrchestration(db.Model, TimestampMixin, SoftDeleteMixin):
    """Represents ."""
    __tablename__ = 'task_orchestrations'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255))
    description = db.Column(db.String(255))
    # 对接的第三方系统名称，默认为自有: "internal"
    origin = db.Column(db.String(255), default="internal")
    orchestration_exe_id = db.Column(db.Integer)
    orchestration_exe_status = db.Column(db.String(255))

    # 表征任务编排的数据结构
    specification = db.Column(db.Text)

    author_id = db.Column(db.Integer)

    activity = db.relationship('DeliveryActivity', uselist=False,
                               backref=db.backref('task_orchestration', lazy='subquery'),
                               lazy='subquery')


class TaskOrchestrationExecution(db.Model, TimestampMixin, SoftDeleteMixin):
    """Represents ."""
    __tablename__ = 'task_orchestration_executions'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_orchestration_id = db.Column(db.Integer, db.ForeignKey('task_orchestrations.id'))
    status = db.Column(db.Enum('PENDING', 'RUNNING', 'SUCCESS', 'FAILURE',
                               'REVERTING', 'REVERTED', 'SUSPEND', name='orchestration_status'),
                       nullable=False, server_default='PENDING')
    trace = db.Column(db.Text)
    executor_id = db.Column(db.BigInteger)


class OrchestrationVertexAtomicTaskMapping(
    db.Model, TimestampMixin, SoftDeleteMixin):
    """Represent mapping between orchestration and atomic tasks"""
    __tablename__ = 'orchestration_vertex_atomic_task_mapping'

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    vertex_id = db.Column(db.String(255))
    task_orchestration_id = db.Column(db.Integer, db.ForeignKey('task_orchestrations.id'),
                                      nullable=False)
    atomic_task_id = db.Column(db.Integer, db.ForeignKey('atomic_tasks.id'),
                               nullable=False)


class AtomicTaskExecution(db.Model, TimestampMixin, SoftDeleteMixin):
    """Represents ."""
    __tablename__ = 'atomic_task_executions'
    # __table_args__ = (schema.UniqueConstraint('task_id', 'host_id'),)

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    status = db.Column(db.Enum('SUCCESS', 'FAILURE', 'RUNNING', 'PENDING', 'REVERTING',
                               'REVERTED', name='atom_status'),
                       nullable=False, server_default='PENDING')

    atomic_task_id = db.Column(db.Integer, db.ForeignKey('atomic_tasks.id'))
    vertex_id = db.Column(db.String(255))
    group_code = db.Column(db.String(128))

    task_orchestration_exe_id = db.Column(db.Integer,
                                          db.ForeignKey('task_orchestration_executions.id'))
    # 执行结果
    result = db.Column(db.Text)
    executor_id = db.Column(db.Integer)

    task_orchestration_exe = db.relationship(
        TaskOrchestrationExecution,
        backref='atomic_task_exes',
        foreign_keys=task_orchestration_exe_id,
        primaryjoin='and_('
                    'AtomicTaskExecution.task_orchestration_exe_id == '
                    'TaskOrchestrationExecution.id,'
                    'AtomicTaskExecution.deleted == False)')

    atomic_task = db.relationship(AtomicTask, backref='atom_exes',
                                  foreign_keys=atomic_task_id,
                                  primaryjoin='and_('
                                              'AtomicTaskExecution.atomic_task_id == '
                                              'AtomicTask.id,'
                                              'AtomicTaskExecution.deleted == False)')


class AtomicTaskExecutionResult(db.Model, TimestampMixin, SoftDeleteMixin):
    """Represents a single execution of the atomic task on a host."""
    __tablename__ = 'atomic_task_execution_results'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # 任务执行结果
    content = db.Column(db.Text)

    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'))
    host_ip = db.Column(db.String(20))

    # failed or success or unreachable
    status = db.Column(db.String(255))

    # host = db.relationship(Host, backref='atomic_task_execution_results')

    task_execution_id = db.Column(db.Integer, db.ForeignKey('atomic_task_executions.id'))
    task_execution = db.relationship(AtomicTaskExecution,
                                     backref='atomic_task_execution_results')
