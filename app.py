import sqlite3
import secrets
import smtplib
import os

from flask import Flask, render_template,request,redirect,url_for,session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

def login_required(func):
	@wraps(func)
	def decorated_function(*args, **kwargs):
		if "user_id" not in session:
			return redirect(url_for("login"))
		return func(*args, **kwargs)
	return decorated_function

def get_db_connection():
	connection = sqlite3.connect("study_manager.db")
	connection.row_factory = sqlite3.Row
	return connection

def send_reset_email(receiver_email,reset_link):
	message = EmailMessage()

	message["Subject"] = "Study Manager - Reset Password"
	message["From"] = os.getenv("MAIL_ADDRESS")
	message["To"] = receiver_email

	message.set_content(f"""
Hello, please click: {reset_link}
""")

	with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
		smtp.login(
		os.getenv("MAIL_ADDRESS"),
		os.getenv("MAIL_PASSWORD")
	)

		smtp.send_message(message)

@app.route("/register", methods=["GET","POST"])
def register():

	today = date.today()

	default_birthdate = today.replace(year = today.year - 18).isoformat()
	today = date.today().isoformat()

	if request.method == "POST":
		name = request.form["name"].strip()
		surname = request.form["surname"].strip()
		displayname = request.form["displayname"].strip()
		birthdate = request.form["birthdate"].strip()
		email = request.form["email"].strip()
		password = request.form.get("password","")
		passcon = request.form.get("passcon","")

		if not name or not surname or not displayname or not birthdate or not email or not password or not passcon:
			return "Please fill in all fields"

		if password != passcon:
			return "Passwords do not match"

		if len(password) < 8:
			return "Password must be at least 8 characters"

		if "@" not in email:
			return "Invalid email address"

		password_hashed = generate_password_hash(password)

		connection = get_db_connection()

		existing_user = connection.execute("""
			SELECT user_id
			FROM users
			WHERE email = ?
		""", (email,)).fetchone()

		if existing_user is not None:
			connection.close()
			return "This email is already registered"

		connection.execute("""
			INSERT INTO users
			(name,surname,display_name,birthdate,email,password_hashed)
			VALUES(?,?,?,?,?,?)
		""", (

			name,
			surname,
			displayname,
			birthdate,
			email,
			password_hashed,
		))	
	
		connection.commit()
		connection.close()

		return redirect(url_for("login"))

	return render_template("login/register.html", today=today, default_birthdate=default_birthdate)

@app.route("/login", methods=["GET","POST"])
def login():
	if request.method == "POST":
		email = request.form["email"]
		password = request.form["password"]
	
		connection = get_db_connection()

		user = connection.execute("""
			SELECT * FROM users
			WHERE email = ?
		""",(email,)).fetchone()	
	
		connection.close()

		if user is None:
			return "Email or password is incorrect"
		if not check_password_hash(user["password_hashed"], password):
			return "Email or password is incorrect"	

		session["user_id"] = user["user_id"]		

		return redirect(url_for("home"))

	return render_template("login/login.html")

@app.route("/resetpassword", methods=["GET","POST"])
def reset():
	if request.method == "POST":
		email = request.form["email"]
		
		connection = get_db_connection()

		user = connection.execute("""
			SELECT * FROM users
			WHERE email = ?
		""",(email,)).fetchone()	


		if user:
			user_id = user["user_id"]
			
			token = secrets.token_urlsafe(32)
			expires_at = datetime.now() + timedelta(minutes=30)

			connection.execute("""
				INSERT INTO password_reset_tokens
				(user_id,token,expires_at)
				VALUES(?,?,?)
			""", (
				user_id,
				token,
				expires_at,
			))	
	
			connection.commit()

			reset_link = url_for(
				"reset_password",
				token=token,
				_external=True 
			)
			
			send_reset_email(email,reset_link)
	
		connection.close()

		return redirect(url_for("reset_sent"))

	return render_template("login/resetpassword.html")

@app.route("/resetpassword/<token>", methods=["GET", "POST"])
def reset_password(token):
	connection = get_db_connection()

	reset_token = connection.execute("""
		SELECT * FROM password_reset_tokens
		WHERE token = ?
	""",(token,)).fetchone()


	if reset_token is None:
		connection.close()
		return "Invalid"

	if reset_token["used"] == 1:
		connection.close()
		return "Already used"

	expires_at = datetime.fromisoformat(reset_token["expires_at"])

	if datetime.now() > expires_at:
		connection.close()
		return "Expired"

	if request.method == "POST":
		newpass = request.form["newpass"]
		passcon = request.form["passcon"]

		if newpass != passcon:
			connection.close()
			return "Passwords do not match"

		if len(newpass) < 8:
			connection.close()
			return "Password must be at least 8 characters"

		user = connection.execute("""
			SELECT password_hashed
			FROM users
			WHERE user_id = ?
		""", (reset_token["user_id"],)).fetchone()

		if check_password_hash(user["password_hashed"], newpass):
			connection.close()
			return "New password cannot be the same as the old password"

		newpass_hashed = generate_password_hash(newpass)


		connection.execute("""
			UPDATE users
			SET password_hashed = ?
			WHERE user_id = ?
		""", (
			newpass_hashed,
			reset_token["user_id"]
		))

		connection.execute("""
			UPDATE password_reset_tokens
			SET  used = 1
			WHERE token = ?	
			""",(token,))
	
		connection.commit()
		connection.close()


		return redirect(url_for("login"))

	connection.close()

	return render_template("login/newpassword.html",token=token)

@app.route("/resetsent")
def reset_sent():
	return render_template("login/resetsent.html")

@app.route("/")
@login_required
def home():
	user_id = session["user_id"]

	connection = get_db_connection()

	user = connection.execute("""
		SELECT display_name
		FROM users
		WHERE user_id = ?
	""", (user_id,)).fetchone()

	upcoming_tasks = connection.execute("""
		SELECT
			tasks.task_id,
			tasks.task_name,
			tasks.description,
			tasks.deadline,
			courses.course_name,
			categories.category_name
		FROM tasks
		INNER JOIN courses
			ON tasks.course_id = courses.course_id
		INNER JOIN categories
			ON tasks.category_id = categories.category_id
		WHERE tasks.user_id = ?
		ORDER BY tasks.deadline
		LIMIT 5
	""", (user_id,)).fetchall()

	connection.close()


	tasks_with_remaining = []

	for task in upcoming_tasks:
		task = dict(task)

		deadline = datetime.fromisoformat(task["deadline"])
		remaining = deadline - datetime.now()

		days = remaining.days
		hours = remaining.seconds // 3600
		minutes = (remaining.seconds % 3600) // 60

		task["deadline_formatted"] = deadline.strftime("%d.%m.%Y %H:%M")
		task["remaining"] = f"{days} days {hours} hours {minutes} minutes"
		task["urgent"] = remaining < timedelta(days=1) and remaining >= timedelta(0)
		task["overdue"] = remaining <= timedelta(0)

		tasks_with_remaining.append(task)
	
	return render_template("index.html", display_name=user["display_name"], upcoming_tasks=tasks_with_remaining)

@app.route("/addtask", methods = ["GET", "POST"])
@login_required
def addtask():

	user_id = session["user_id"]

	connection = get_db_connection()
	
	if request.method == "POST":
		category_id = request.form["category_id"].strip()
		course_id = request.form["course_id"].strip()

		if category_id == "new":

			newcat = request.form["newcat"].strip()

			connection.execute("""
				INSERT INTO categories
				(category_name, user_id)
				VALUES (?, ?)
			""", (
				newcat,
				user_id
			))

			category_id = connection.execute(
				"SELECT last_insert_rowid()"
			).fetchone()[0]

		if category_id is None:
			connection.close()
			return "Invalid category"

		category = connection.execute("""
					SELECT category_id
					FROM categories
					WHERE category_id = ?
					AND user_id = ?
				""", (category_id, user_id)).fetchone()

		if category is None:
			connection.close()
			return "Invalid category"

		if course_id == "new":

			newcourse = request.form["newcourse"].strip()

			connection.execute("""
				INSERT INTO courses
				(course_name, user_id)
				VALUES (?, ?)
			""", (
				newcourse,
				user_id
			))

			course_id = connection.execute(
				"SELECT last_insert_rowid()"
			).fetchone()[0]

		if course_id is None:
			connection.close()
			return "Invalid course"

		course = connection.execute("""
			SELECT course_id
			FROM courses
			WHERE course_id = ?
			AND user_id = ?
		""", (course_id, user_id)).fetchone()

		if course is None:
			connection.close()
			return "Invalid course"

		task_name = request.form["taskname"]
		description = request.form["taskdesc"]
		deadline = request.form["deadline"]
		
		connection.execute("""
			INSERT INTO tasks
			(task_name, description, deadline, course_id, category_id, user_id)
			VALUES (?, ?, ?, ?, ?, ?)
		""", (
			task_name,
			description,
			deadline,
			course_id,
			category_id,
			user_id
		))

		connection.commit()
		connection.close()

		return redirect(url_for("tasks"))

	categories = connection.execute("""
		SELECT * FROM categories
		WHERE user_id = ?
		ORDER BY category_name
	""", (user_id,)).fetchall()

	courses = connection.execute("""
		SELECT * FROM courses
		WHERE user_id = ?
		ORDER BY course_name
	""", (user_id,)).fetchall()
		
	connection.close()

	return render_template(
		"tasks/addtask.html",
		courses=courses,
		categories=categories
	)

@app.route("/tasks")
@login_required
def tasks():
	user_id = session["user_id"]

	connection = get_db_connection()

	tasks = connection.execute("""
		SELECT
			tasks.task_id,
			tasks.task_name,
			tasks.description,
			tasks.deadline,
			courses.course_name,
			categories.category_name
		FROM tasks
		INNER JOIN courses
			ON tasks.course_id = courses.course_id
		INNER JOIN categories
			ON tasks.category_id = categories.category_id

		WHERE tasks.user_id = ?

		ORDER BY tasks.deadline
	""", (user_id,)).fetchall()

	connection.close()	

	tasks = [dict(task) for task in tasks]	

	for task in tasks:
		deadline = datetime.fromisoformat(task["deadline"])
		task["deadline_formatted"] = deadline.strftime("%d.%m.%Y %H:%M")	

	return render_template("tasks/tasks.html", tasks=tasks)

@app.route("/task/<int:task_id>")
@login_required
def task_detail(task_id):

	user_id = session["user_id"]

	connection = get_db_connection()

	task = connection.execute("""
		SELECT
			tasks.task_id,
			tasks.task_name,
			tasks.description,
			tasks.deadline,
			courses.course_name,
			categories.category_name
		FROM tasks
		INNER JOIN courses
			ON tasks.course_id = courses.course_id
		INNER JOIN categories
			ON tasks.category_id = categories.category_id
		WHERE tasks.task_id = ?
		AND tasks.user_id = ?
	""", (task_id, user_id)).fetchone()

	connection.close()

	if task is None:
		return "Task not found"

	deadline = datetime.fromisoformat(task["deadline"])
	remaining = deadline - datetime.now()

	days = remaining.days
	hours = remaining.seconds // 3600
	minutes = (remaining.seconds % 3600) // 60

	task = dict(task)
	task["remaining"] = f"{days} days {hours} hours {minutes} minutes"

	return render_template(
		"tasks/taskdetail.html",
		task=task,
		previous_page=request.referrer
	)

@app.route("/edittask/<int:task_id>", methods=["GET", "POST"])
@login_required
def edittask(task_id):

	user_id = session["user_id"]

	connection = get_db_connection()

	task = connection.execute("""
		SELECT *
		FROM tasks
		WHERE task_id = ?
		AND user_id = ?
	""", (task_id, user_id)).fetchone()

	if task is None:
		connection.close()
		return "Task not found"

	if request.method == "POST":

		category_id = request.form["category_id"]
		course_id = request.form["course_id"]

		if category_id == "new":

			newcat = request.form["newcat"]

			connection.execute("""
				INSERT INTO categories
				(category_name, user_id)
				VALUES (?, ?)
			""", (
				newcat,
				user_id
			))

			category_id = connection.execute(
				"SELECT last_insert_rowid()"
			).fetchone()[0]

		if course_id == "new":

			newcourse = request.form["newcourse"]

			connection.execute("""
				INSERT INTO courses
				(course_name, user_id)
				VALUES (?, ?)
			""", (
				newcourse,
				user_id
			))

			course_id = connection.execute(
				"SELECT last_insert_rowid()"
			).fetchone()[0]

		category = connection.execute("""
			SELECT category_id
			FROM categories
			WHERE category_id = ?
			AND user_id = ?
		""", (category_id, user_id)).fetchone()

		if category is None:
			connection.close()
			return "Invalid category"

		course = connection.execute("""
			SELECT course_id
			FROM courses
			WHERE course_id = ?
			AND user_id = ?
		""", (course_id, user_id)).fetchone()

		if course is None:
			connection.close()
			return "Invalid course"

		task_name = request.form["taskname"]
		description = request.form["taskdesc"]
		deadline = request.form["deadline"]

		connection.execute("""
			UPDATE tasks
			SET task_name = ?,
				description = ?,
				deadline = ?,
				course_id = ?,
				category_id = ?
			WHERE task_id = ?
			AND user_id = ?
		""", (
			task_name,
			description,
			deadline,
			course_id,
			category_id,
			task_id,
			user_id
		))

		connection.commit()
		connection.close()

		return redirect(url_for("tasks"))

	categories = connection.execute("""
		SELECT *
		FROM categories
		WHERE user_id = ?
		ORDER BY category_name
	""", (user_id,)).fetchall()

	courses = connection.execute("""
		SELECT *
		FROM courses
		WHERE user_id = ?
		ORDER BY course_name
	""", (user_id,)).fetchall()

	connection.close()

	return render_template(
		"tasks/edittask.html",
		task=task,
		categories=categories,
		courses=courses
	)

@app.route("/delete_task/<int:task_id>", methods=["POST"])
@login_required
def delete_task(task_id):

	user_id = session["user_id"]

	connection = get_db_connection()

	connection.execute("""
		DELETE FROM tasks
		WHERE task_id = ? AND user_id = ?
	""", (task_id, user_id))

	connection.commit()
	connection.close()

	return redirect(url_for("tasks"))


@app.route("/profile")
@login_required
def profile():

	user_id = session["user_id"]

	connection = get_db_connection()

	user = connection.execute("""
		SELECT * FROM users
		WHERE user_id = ?
	""", (user_id,)).fetchone()
	
	connection.close()


	return render_template("profile/profile.html", user=user)

@app.route("/editprofile", methods=["GET","POST"])
@login_required
def editprofile():

	user_id = session["user_id"]

	if request.method == "POST":
		
		name = request.form["name"]
		surname = request.form["surname"]
		display_name = request.form["display_name"]
		birthdate = request.form["birthdate"]
		email = request.form["email"]

		connection = get_db_connection()

		existing_user = connection.execute("""
			SELECT user_id
			FROM users
			WHERE email = ?
			AND user_id != ?
		""", (email, user_id)).fetchone()

		if existing_user is not None:
			connection.close()
			return "This email is already in use"
			
		connection.execute(""" 
			UPDATE users
			SET name = ?,
				surname = ?,
				display_name = ?,
				birthdate = ?,
				email = ?
			WHERE user_id = ?
		""", (
			name,
			surname,
			display_name,
			birthdate,
			email,
			user_id
		))
	
	
		connection.commit()
		connection.close()
		
		return redirect(url_for("profile"))

	connection = get_db_connection()

	user = connection.execute("""
		SELECT * FROM users
		WHERE user_id = ?
	""", (user_id,)).fetchone()
	
	connection.close()


	return render_template("profile/editprofile.html", user=user)

@app.route("/changepassword", methods=["GET","POST"])
@login_required
def changepassword():
	
	user_id = session["user_id"]

	if request.method == "POST":
		
		oldpass = request.form["oldpass"]
		newpass = request.form["newpass"]
		conpass = request.form["conpass"]
		
		connection = get_db_connection()
		
		user = connection.execute("""
			SELECT password_hashed FROM users WHERE user_id = ?
		""", (user_id,)).fetchone()	
	
		if len(newpass) < 8:
			connection.close()
			return "Password must be at least 8 characters"

		if not check_password_hash(user["password_hashed"], oldpass):
			connection.close()
			return "Old password is incorrect"
		if newpass != conpass:
			connection.close()
			return "Password do not match"

		newpass_hashed = generate_password_hash(newpass)
		
		connection.execute("""
			UPDATE users
			SET password_hashed = ?
			WHERE user_id = ?
		""", (newpass_hashed, user_id))
	
		connection.commit()
		connection.close()
		
		return redirect(url_for("profile"))


	return render_template("profile/changepassword.html")

@app.route("/logout")
@login_required
def logout():
	session.clear()
	return redirect(url_for("login"))



if __name__ == "__main__":
	app.run(debug=True)