from flask import Flask, render_template, request, redirect, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import mysql.connector
import configparser
import boto3

configParser = configparser.RawConfigParser()
configFilePath = r'config.txt'
configParser.read(configFilePath)

access_key = configParser.get('My-Section', 'aws_access_key')
secret_key = configParser.get('My-Section', 'aws_secret_key')
bucket_name = configParser.get('My-Section', 'bucket_name')
bucket_region = configParser.get('My-Section', 's3_bucket_region')

app = Flask(__name__)
app.secret_key = configParser.get('My-Section', 'flask_secret_key')

mydb = mysql.connector.connect(
    host=configParser.get('My-Section', 'db_host'),
    user=configParser.get('My-Section', 'db_user'),
    password=configParser.get('My-Section', 'db_password'),
    database=configParser.get('My-Section', 'db_database'))

print(mydb)
mycursor = mydb.cursor()


@app.route('/')
def home():
    if 'token' in session:
        token = session['token']
        sql = "select username from users where token = %s"
        val = (token,)
        mycursor.execute(sql, val)
        user = mycursor.fetchone()
        if user:
            return render_template('index.html', username=user[0])
    return render_template('index.html', username=None)


@app.route('/signup', methods=['GET'])
def signup():
    return render_template('signup.html')


@app.route('/signup', methods=['POST'])
def create_user():
    print(session)
    username = request.form['username']
    password = request.form['password']
    password = generate_password_hash(password)
    sql = "select username from users where username = %s"
    val = (username, )
    mycursor.execute(sql, val)
    user = mycursor.fetchone()
    if user is not None:
        return render_template('signup.html', error="User already exists")
    sql = "insert into users(username, password) values(%s,%s)"
    val = (username, password)
    mycursor.execute(sql, val)
    mydb.commit()
    return redirect('/login')


@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_user():
    username = request.form['username']
    password = request.form['password']
    sql = "select username,password,token from users where username = %s"
    val = (username,)
    mycursor.execute(sql, val)
    user = mycursor.fetchone()
    if user is not None:
        if check_password_hash(user[1], password):
            token = secrets.token_hex(8)
            session['token'] = token
            sql = "UPDATE users SET token = %s WHERE username = %s"
            val = (token, user[0])
            mycursor.execute(sql, val)
            mydb.commit()
            return redirect("/")
        return render_template('login.html', error="Invalid password")
    return render_template('login.html', error="User not found")


@app.route('/upload', methods=['GET'])
def get_upload():
    if 'token' in session:
        token = session['token']
        sql = "select username from users where token = %s"
        val = (token,)
        mycursor.execute(sql, val)
        user = mycursor.fetchone()
        if user:
            return render_template('upload.html', username=user[0])
    return render_template('upload.html', username=None)


@app.route('/upload', methods=['POST'])
def upload_file():
    s3 = boto3.client('s3', aws_access_key_id=access_key,
                      aws_secret_access_key=secret_key)
    f = request.files['file']
    secure_filename_str = secure_filename(f.filename)
    f.save(secure_filename_str)
    if 'token' in session:
        token = session['token']
        sql = "select username from users where token = %s"
        val = (token,)
        mycursor.execute(sql, val)
        user = mycursor.fetchone()
        s3.upload_file(Filename=secure_filename_str,
                       Bucket=bucket_name,Key=f'{user[0]}/{secure_filename_str}')
        return 'file uploaded successfully'
    return redirect('/')


@app.route('/list', methods=['GET'])
def list_files():
    if 'token' in session:
        token = session['token']
        sql = "select username from users where token = %s"
        val = (token,)
        mycursor.execute(sql, val)
        user = mycursor.fetchone()
        if user:
            s3 = boto3.client('s3', aws_access_key_id=access_key, aws_secret_access_key=secret_key)
            objects = s3.list_objects_v2(Bucket=bucket_name, Prefix=f"{user[0]}/")
            table_data = []
            count = 1
            for obj in objects['Contents']:
                link = f"https://{bucket_name}.s3.{bucket_region}.amazonaws.com/{obj['Key']}"
                last_position_ = obj['Key'].rfind('/')
                prefix = obj['Key'][0:last_position_+1]
                table_item = {"s_no": count, "file_name": obj['Key'].removeprefix(prefix), "hyperlink": link}
                table_data.append(table_item)
                count = count + 1
            headers = ['S. No', 'File Name']
            return render_template('list.html', headers=headers, tableData=table_data, username=user[0])
    return render_template('index.html', username=None)


@app.route('/logout')
def logout():
    if 'token' in session:
        token = session['token']
        sql = "update users set token = %s where token = %s"
        val = (None, token)
        mycursor.execute(sql, val)
        mydb.commit()
    session.pop('token', None)
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5003)
