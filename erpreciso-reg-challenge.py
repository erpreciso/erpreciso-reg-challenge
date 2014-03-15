# copyright erpreciso

import webapp2
import re
import os
import jinja2
import time
import random
import string
import hashlib
import json
import logging

from google.appengine.api import memcache

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
		autoescape = True)

HIT_TIME = time.time()
PLINK_TIME = time.time()

def blog_key(bkey = 'default'):
	return db.Key.from_path("Entries", bkey)
	
def user_key(ukey = 'default'):
	return db.Key.from_path("People", ukey)

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s|%s" % (h,salt)

def valid_pw(name, pw, h, salt):
	#salt = h.split('|')[1]
	return h == make_pw_hash(name, pw, salt)

class Entries(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	
class People(db.Model):
	username = db.StringProperty()
	password = db.StringProperty()
	email = db.TextProperty()
	created =  db.DateTimeProperty(auto_now_add = True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
	
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

def top_10(update = False):
	key = 'top'
	all_entries = memcache.get(key)
	if all_entries is None or update:
		all_entries = db.GqlQuery("SELECT * from Entries ORDER BY created DESC LIMIT 10")
		memcache.set(key, all_entries)
		global HIT_TIME
		HIT_TIME = time.time()
	return all_entries

class MainPage(Handler):
	def render_main_page(self):
		global HIT_TIME
		top = top_10()
		seconds_after_query = int(time.time() - HIT_TIME)
		self.render("main_page.html", hit_time = seconds_after_query, all_entries = top)

	def get(self):
		self.render_main_page()

def cplink(pid, update = False):
	mkey = pid
	t = memcache.get(mkey)
	#logging.error("PLINK")
	if t is None or update:
		key = db.Key.from_path("Entries", int(pid), parent = blog_key())
		t = db.get(key)
		memcache.set(mkey, t)
		global PLINK_TIME
		PLINK_TIME = time.time()
		
	return t

class Plink(Handler):
	def render_plink(self, plink_id = "", subject = "", content = "", created = "", seconds_after_query = ""):
		self.render("plink_page.html",plink_id = plink_id, subject = subject, content = content, created = created, hit_time = seconds_after_query)
	
	def get(self, product_id):
		t = cplink(product_id)
		a = int(time.time() - PLINK_TIME)
		date = t.created.strftime("%a %b %d  %H:%M:%S %Y")
		self.render_plink(plink_id = t.key(), subject = t.subject, content = t.content, created = date, seconds_after_query = a)
	
class NewPost(Handler):
	def render_new_post(self, message = "", subject = "", content = ""):
		self.render("new_post.html", message = message, subject = subject, content = content)

	def get(self):
		self.render_new_post()
	
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		if subject and content:
			e = Entries(parent = blog_key(), subject = subject, content = content)
			e.put()
			memcache.delete('top')
			self.redirect('/blog/%s' % str(e.key().id()))
		else:
			message = "subject and content, please"
			self.render_new_post(message, subject, content)

class LoginClass(Handler):
	
	def write_login(self, username = "", login_error = ""):
		self.render("login_page.html",username = username,
										login_error = login_error)
	def get(self):
		self.write_login()
	
	def post(self):
		username=self.request.get("username")
		password=self.request.get("password")
		if username == "" or password == "":
			self.write_login(login_error = "Invalid login")
		else:
			ck = db.GqlQuery("SELECT * FROM People WHERE username = :1", username)
			u = ck.get()
			if u:
				db_password = u.password
				salt = db_password.split('|')[1]
				user_password = make_pw_hash(username, password, salt)
				if user_password == db_password:
					self.response.headers.add_header('Set-Cookie', 'udacity=%s|%s; Path=/' % (str(u.key().id()),str(user_password)))
					self.redirect("/blog/welcome")			
			self.write_login(login_error = "Invalid login")

class DeleteDBClass(Handler):
	
	def get(self):
		tutt = db.GqlQuery("SELECT * FROM People")
		for un in tutt:
			un.delete()
		self.response.out.write("<h1>Database cancellato</h1>")

class SignupClass(Handler):
    
	def write_signup(self,username="",email="",username_error="",password_missing_error_sw=False,password_match_error_sw=False,mail_error_sw=False):
		if password_missing_error_sw:
			password_missing_error="That wasn't a valid password."
		else:
			password_missing_error=""
		if password_match_error_sw:
			password_match_error="Your passwords didn't match."
		else:
			password_match_error=""
		if mail_error_sw:
			mail_error="That's not a valid email."
		else:
			mail_error=""
		tutt = db.GqlQuery("SELECT * FROM People ORDER BY created DESC LIMIT 10")
		self.render("signup_page.html",username = username,
												email = email,
												username_error = username_error,
												password_missing_error = password_missing_error,
												password_match_error = password_match_error,
												mail_error = mail_error,
												tutt = tutt)

	def get(self):
		self.write_signup()

	def post(self):
		username=self.request.get("username")
		password=self.request.get("password")
		verify_password=self.request.get("verify")
		email=self.request.get("email")
		
		#verifica presenza username
		username_error_sw = False
		username_error=""
		if username == "":
			username_error = "That's not a valid username."
			username_error_sw = True
		#verifica correttezza username
		username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		if username_re.match(username) == None:
			username_error_sw = True
		#verifica presenza password
		password_missing_error_sw = False
		if password == "":
			password_missing_error_sw = True
		#verifica correttezza password
		password_re = re.compile(r"^.{3,20}$")
		if password_re.match(password) == None:
			password_missing_error_sw = True
		#verifica consistenza password
		password_match_error_sw = False
		if password != verify_password:
			password_match_error_sw = True
		#verifica correttezza email
		mail_error_sw = False
		if email != "":
			mail_re=re.compile(r"^[\S]+@[\S]+\.[\S]+$")
			if mail_re.match(email) == None:
				mail_error_sw = True
		if password_match_error_sw or username_error_sw or password_missing_error_sw or mail_error_sw == True:
			self.write_signup(username,email,username_error,password_missing_error_sw,
								password_match_error_sw,mail_error_sw)
		else:
			ck = db.GqlQuery("SELECT * FROM People WHERE username = :1", username)
			if not ck.get():
				u = People(parent = user_key())
				u.username = username
				u.password = make_pw_hash(username, password)
				if email != "":
					u.email = email
				k = u.put()
				self.response.headers.add_header('Set-Cookie', 'udacity=%s|%s; Path=/' % (str(k.id()),u.password))
				self.redirect("/blog/welcome")
			else:
				username_error = "That user already exists"
				self.write_signup(username,email,username_error,password_missing_error_sw,
								password_match_error_sw,mail_error_sw)

class WelcomeClass(Handler):

	def get(self):
		c = self.request.cookies.get('udacity')
		if c:
			user_id = c.split('|')[0]
			user_pswsalt = '%s|%s' % (c.split('|')[1], c.split('|')[2])
			key = db.Key.from_path("People", int(user_id), parent = user_key())
			t = db.get(key)
			if t:
				db_user = t.username
				db_pswsalt = t.password
				if db_pswsalt != user_pswsalt:
					self.redirect("/blog/signup")
				self.response.out.write("<h1>Welcome, %s!</h1>" % t.username)		
			else:
				self.redirect("/blog/signup")			
		else:
			self.redirect("/blog/signup")

class LogoutClass(Handler):
	
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'udacity=; Path=/')
		self.redirect("/blog/signup")

class JsonMainPage(Handler):
	def get(self):
		all_entries = db.GqlQuery("SELECT * from Entries ORDER BY created DESC LIMIT 10")
		u = []
		for s in all_entries:
			date = s.created.strftime("%a %b %d  %H:%M:%S %Y")
			outp = {"content":s.content,"subject":s.subject,"created":date}
			u.append(outp)
		self.response.headers['Content-Type'] = 'application/json'
		self.write(json.dumps(u))

class JsonPlink(Handler):
	def get(self, product_id):
		key = db.Key.from_path("Entries", int(product_id), parent = blog_key())
		t = db.get(key)
		date = t.created.strftime("%a %b %d  %H:%M:%S %Y")
		outp = {"content":t.content,"subject":t.subject,"created":date}
		self.response.headers['Content-Type'] = 'application/json'
		self.write(json.dumps(outp))

class FlushClass(Handler):
	def get(self):
		memcache.flush_all()
		self.redirect("/blog")
		
app = webapp2.WSGIApplication([('/blog/?', MainPage),
								('/blog/.json', JsonMainPage),
								('/blog/newpost', NewPost),
								('/blog/(\d+)', Plink),
								('/blog/(\d+).json', JsonPlink),
								("/blog/logout",LogoutClass),
								("/blog/login",LoginClass),
								("/blog/signup",SignupClass),
								("/blog/welcome",WelcomeClass),
								("/blog/delete",DeleteDBClass),
								("/blog/flush",FlushClass)
								], debug=True)

