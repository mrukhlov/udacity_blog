#encoding:utf8

import os
import webapp2
import jinja2
import string
import re
import hashlib
import random
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

class Utils():

	global secret
	secret = 'hmac_secret'

	def valid_username(self, username):
		if username:
			username_match = re.match("^[a-zA-Z0-9_-]{3,20}$", username)
			if username_match:
				return username


	def valid_password(self, password):
		if password:
			password_match = re.match("^.{3,20}$", password)
			if password_match:
				return password


	def valid_email(self, email):
		if email:
			email_match = re.match("^[\S]+@[\S]+.[\S]+$", email)
			if email_match:
				return email

	def make_salt(self):
		return ''.join(random.choice(string.letters) for x in range(5))


	def make_pw_hash(self, name, pw, salt=None):
		if not salt:
			salt = self.make_salt()
		h = hashlib.sha256(name + pw + salt).hexdigest()
		return '%s|%s' % (h, salt)


	def valid_pw(self, name, pw, h):
		salt = h.split('|')[1]
		return h == self.make_pw_hash(name, pw, salt)

	def check_cookie(self, cookie):
		if hashlib.sha256(cookie.split('|')[0]).hexdigest() == cookie.split('|')[1]:
			return True

	def check_if_user(self, request, dbase):
		username_cookie_str = request.cookies.get('username')
		if username_cookie_str:
			valid_cookie = self.check_cookie(username_cookie_str)
			if valid_cookie:
				return True

class Handler(webapp2.RequestHandler):

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

'''Auth part'''

class Register(db.Model):
	username = db.StringProperty(required=True)
	password = db.TextProperty(required=True)
	email = db.TextProperty()

class Signup(Handler, Utils):


	def get(self):
		self.render('signup.html')

	def post(self):

		user_username = self.request.get('username')
		user_pass = self.request.get('password')
		user_verify = self.request.get('verify')
		user_email = self.request.get('email')

		params = dict(username=user_username, email=user_email)

		username = self.valid_username(user_username)
		if not username:
			params['error_username'] = "Invalid username"

		password = self.valid_password(user_pass)
		if not password:
			params['error_pass'] = "Invalid password"
		else:
			if user_verify and password == user_verify:
				user_verify = password
			else:
				params['error_passv'] = "Invalid verification"

		if user_email:
			email = self.valid_email(user_email)
			if not email:
				params['error_email'] = "That's not a valid email."
		else:
			email = False

		if username and password and user_verify and (email == False or email):
			q = db.Query(Register)
			user_entry = q.filter('username =', username).get()
			if user_entry:
				params['error_username'] = "User already exists."
				self.render('signup.html', **params)
			else:
				hash_usrname = '%s|%s' % (username, hashlib.sha256(username).hexdigest())
				self.response.headers.add_header('Set-Cookie', str('username=' + hash_usrname))
				passw = password + secret
				a = Register(username=username, password=hashlib.sha256(passw).hexdigest())
				a.put()
				self.redirect('/welcome')
		else:
			self.render('signup.html', **params)

class Login(Handler):

	def get(self):
		self.render('login.html')

	def post(self):
		user_username = self.request.get('username')
		user_pass = self.request.get('password')
		params = dict(username=user_username)
		if user_pass and user_username:
			q = db.Query(Register)
			user_entry = q.filter('username =', user_username).get()
			if user_entry:
				if user_entry.password == hashlib.sha256(user_pass + secret).hexdigest():
					hash_usrname = '%s|%s' % (user_username, hashlib.sha256(user_username).hexdigest())
					self.response.headers.add_header('Set-Cookie', str('username=' + hash_usrname))
					self.redirect('/welcome')
				else:
					params['error_pass'] = "That's not a valid password."
					self.render('login.html', **params)
			else:
				params['error_username'] = "That's not a valid username."
				self.render('login.html', **params)
		else:
			params['error_username'] = "That's not a valid username."
			params['error_pass'] = "That's not a valid password."
			self.render('login.html', **params)

class Logout(Handler):

	def get(self):
		self.response.headers.add_header('Set-Cookie', str('username='))
		self.redirect('/signup')

class Welcome(Handler):

	def get(self):

		valid_user_cookie = self.check_if_user(self.request, Register)
		username_cookie_str = self.request.cookies.get('username')

		q = db.Query(Register)
		if username_cookie_str:
			if valid_user_cookie:
				self.render('welcome.html', username = username_cookie_str.split('|')[0])
			else:
				self.redirect('/signup')
		else:
			self.redirect('/signup')

'''Blog part'''

class Blog(db.Model):
	title = db.StringProperty(required=True)
	post = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)
	author = db.StringProperty()
	likes = db.IntegerProperty()
	# comments = db.ListProperty(basestring)
	comments = db.StringProperty()

class Comments(db.Model):
	post_id = db.IntegerProperty()
	comment = db.TextProperty(required=True)
	author = db.StringProperty()
	created = db.DateTimeProperty(auto_now_add=True)

class Likes(db.Model):
	post_id = db.IntegerProperty()
	author = db.StringProperty()

class MainPage(Handler):

	def render_front(self, title='', art='', error=''):

		username = self.request.cookies.get('username')

		posts = Blog.all().order('-created')
		likes = Likes.all()
		if username:
			self.render(
				'index.html',
				title=title,
				art=art,
				error=error,
				posts=posts,
				likes=likes,
				username=username.split('|')[0]
			)
		else:
			self.redirect('/signup')

	def get(self):
		self.render_front()

class CreatePost(Handler):

	def render_front(self, title='', art='', error=''):
		self.render('create_post.html', title=title, art=art, error=error)

	def get(self):

		valid_user_cookie = self.check_if_user(self.request, Register)
		if valid_user_cookie:
			self.render_front()
		else:
			self.redirect('/login')

	def post(self):
		valid_user_cookie = self.check_if_user(self.request, Register)
		if valid_user_cookie:
			title = self.request.get('subject')
			post = self.request.get('content')
			author = self.request.cookies.get('username')
			error = ''

			if title and post:
				a = Blog(title = title, post = post, author = author.split('|')[0], likes = 0)
				a.put()
				id = a.key().id()
				self.redirect('/blog/'+str(id))
			else:
				error = 'We need both title and blog text!'
				self.render_front(title, post, error)
		else:
			self.redirect('/login')

class EditPost(Handler):

	def get(self):

		post_id = self.request.cookies.get('post_id')

		valid_user_cookie = self.check_if_user(self.request, Register)
		if valid_user_cookie:
			post_to_edit = Blog.get_by_id(int(post_id))
			self.render('edit_post.html', title=post_to_edit.title, post_text=post_to_edit.post, post_id=post_id)
		else:
			self.redirect('/login')

	def post(self):

		valid_user_cookie = self.check_if_user(self.request, Register)
		if valid_user_cookie:

			title = self.request.get('subject')
			post = self.request.get('content')

			author = self.request.cookies.get('username')
			post_id = self.request.cookies.get('post_id')

			post_to_edit = Blog.get_by_id(int(post_id))
			post_text = post_to_edit.post

			error = ''

			if title and post:
				post_to_edit = Blog.get_by_id(int(post_id))
				if author == post_to_edit.author:
					post_to_edit.title = title
					post_to_edit.post = post
					post_to_edit.put()
					self.redirect('/blog/'+str(post_id))
				else:
					error = 'You must be an author of the post'
					self.render('edit_post.html', title=title, post_text=post_text, post_id=post_id, error=error)
			else:
				error = 'We need both title and blog text!'
				# self.render_front(title, post, error)
				self.render('edit_post.html', title=title, post=post, error=error)
		else:
			self.redirect('/login')

class BlogPage(Handler):

	def get(self, blog_id):

		username = self.request.cookies.get('username')

		likes = Likes.all()
		params = dict()
		remove_error = self.request.get('remove_error')
		like_error = self.request.get('like_error')
		like_duplicate = self.request.get('like_duplicate')
		comment_error = self.request.get('comment_error')
		if remove_error:
			params['error_username'] = 'You cannot delete this post'
		if like_error:
			params['error_username'] = 'You cannot like your own post'
		if like_duplicate:
			params['error_username'] = 'You can like post only once'
		if comment_error:
			params['comment_remove_error'] = 'You can only remove your own comments.'

		q = Comments.all()
		comment_entry = q.filter('post_id =', int(blog_id)).order('-created').fetch(limit=10)

		blog_post = Blog.get_by_id(int(blog_id))
		l = likes.filter('post_id =', int(blog_id)).count()

		if blog_post:
			self.response.headers.add_header('Set-Cookie', str('post_id=' + str(blog_id)))
			self.render('post.html', post=blog_post, comments=comment_entry, likes=l, username=username.split('|')[0], **params)
		else:
			self.redirect('/blog')

class MainRedirect(Handler):

	def get(self):
		self.redirect('/welcome')

class AddComment(Handler):

	def post(self):

		valid_user_cookie = self.check_if_user(self.request, Register)
		if valid_user_cookie:
			post_id = self.request.cookies.get('post_id')
			author = self.request.cookies.get('username').split('|')[0]
			user_comment = self.request.get('comment')

			if user_comment:
				blog_post = Comments(comment=str(user_comment), post_id=int(post_id), author=author)
				blog_post.put()
				comment_id = blog_post.key().id()

			self.redirect('/blog/' + str(post_id))
		else:
			self.redirect('/login')

class RemovePost(Handler, Utils):

	def post(self):
		valid_user_cookie = self.check_if_user(self.request, Register)
		if valid_user_cookie:
			user = self.request.cookies.get('username')
			post_id = self.request.cookies.get('post_id')
			post_to_delete = Blog.get_by_id(int(post_id))
			post_key = post_to_delete.key()

			check_user = self.check_cookie(user)

			if check_user and user.split('|')[0] == post_to_delete.author:
				db.delete(post_key)
				self.redirect('/blog')
			else:
				self.redirect('/blog/' + str(post_id)+'?remove_error=True')
		else:
			self.redirect('/login')

class LikePost(Handler, Utils):

	def post(self):

		valid_user_cookie = self.check_if_user(self.request, Register)
		if valid_user_cookie:

			user = self.request.cookies.get('username')
			author = self.request.cookies.get('username').split('|')[0]
			post_id = int(self.request.cookies.get('post_id'))
			post_to_like = Blog.get_by_id(int(post_id))

			check_user = self.check_cookie(user)
			like_check = Likes.all().filter('author =', author).count()

			if check_user and user.split('|')[0] == post_to_like.author:
				self.redirect('/blog/' + str(post_id)+'?like_error=True')
			elif like_check > 0:
				self.redirect('/blog/' + str(post_id) + '?like_duplicate=True')
			else:

				like = Likes(post_id=post_id, author=author)
				like.put()
				self.redirect('/blog/' + str(post_id))
		else:
			self.redirect('/login')

class RemoveComment(Handler):

	def get(self, comment_id):

		post_id = self.request.cookies.get('post_id')
		user = self.request.cookies.get('username')

		comment_to_delete = Comments.get_by_id(int(comment_id))
		if comment_to_delete.author == user.split('|')[0]:
			comment_key = comment_to_delete.key()
			db.delete(comment_key)

			self.redirect('/blog/' + str(post_id))
		else:
			self.redirect('/blog/' + str(post_id)+'?comment_error=True')

app = webapp2.WSGIApplication([
	('/', MainRedirect),
	('/blog', MainPage),
	('/blog/newpost', CreatePost),
	('/blog/(\d+)', BlogPage),
	('/blog/remove_comment/(\d+)', RemoveComment),
	('/blog/remove_post', RemovePost),
	('/blog/like_post', LikePost),
	('/blog/edit_post', EditPost),
	('/signup', Signup),
	('/welcome', Welcome),
	('/login', Login),
	('/logout', Logout),
	('/blog/add_comment', AddComment),
], debug=True)