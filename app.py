from flask import Flask, render_template, request, url_for, redirect, session
import pymongo
import bcrypt
import dotenv
import os

dotenv_file = '.env'
if os.path.exists(dotenv_file):
    dotenv.load_dotenv(dotenv_file)  

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
client = pymongo.MongoClient(os.environ["CLIENT_ID"])
db = client.get_database('total_records')
records = db.register

@app.route("/", methods = ['POST','GET'])
def index():
    message = ''
    if "email" in session:
        return redirect(url_for("logged_in"))
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")
        
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        
        if email_found:
            message = 'This email already exists in database'
            return render_template('index.html',message=message)
        if password1 != password2:
            message = 'Passwords should match'
            return render_template('index.html',message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'),bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            records.insert_one(user_input)

            user_data = records.find_one({"email": email})
            new_email = user_data['email']

            return render_template('logged_in.html', email=new_email)
    return render_template('index.html')

@app.route("/login",methods = ["POST","GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("logged_in"))
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            password_check = email_found['password']

            if bcrypt.checkpw(password.encode('utf-8'), password_check):
                session["email"] = email_val
                return redirect(url_for('logged_in'))
            else:
                if "email" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong Password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)

@app.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        return render_template('logged_in.html',email=email)
    else:
        return redirect(url_for("login"))

@app.route('/logout',methods=["POST","GET"])
def logout():
    if "email" in session:
        session.pop("email",None)
        return render_template("signout.html")
    else:
        return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=False)
