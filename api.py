#!/usr/bin/python3
#
# api.py - Flask REST API to render EML files
#
# Author: Xavier Mertens <xavier@rootshell.be>
# Copyright: GPLv3 (http://gplv3.fsf.org)
# Fell free to use the code, but please share the changes you've made
#
# Todo
# - "offline" mode when rendering HTML code
#

import os
import sys
import email
import email.header
import quopri
import hashlib
import logging
import base64
import zipfile
import string
import random
import json
from time import strftime
from logging.handlers import RotatingFileHandler

from json import dumps

try:
    from flask import Flask, request, jsonify, send_file, Response
    from flask_restful import Resource, Api
    from flask_httpauth import HTTPBasicAuth
    from flask_sqlalchemy import SQLAlchemy
except:
    print('[ERROR] flask module not installed ("pip install flask")')
    sys.exit(1)

try:
    from passlib.apps import custom_app_context as pwd_context
except:
    print('[ERROR] passlib module is not installed ("pip install passlib")')
    sys.exit(1)

try:
    import imgkit
except:
    print('[ERROR] imgkit module not installed ("pip install imgkit")')
    sys.exit(1)

try:
    from PIL import Image
except:
    print('[ERROR] pillow module not installed ("pip install pillow")')
    sys.exit(1)

__author__     = "Xavier Mertens"
__license__    = "GPL"
__version__    = "1.0"
__maintainer__ = "Xavier Mertens"
__email__      = "xavier@erootshell.be"
__name__       = "EMLRender"

app        = Flask(__name__)
api        = Api(app)
logger     = None
dumpDir    = 'dumps'
textTypes  = [ 'text/plain', 'text/html' ]
imageTypes = [ 'image/gif', 'image/jpeg', 'image/png' ]
basic_auth = HTTPBasicAuth()

app.config['BASIC_AUTH_REALM'] = 'EMLRender Authentication'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    uid           = db.Column(db.Integer, primary_key = True)
    username      = db.Column(db.String(32), index = True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

@basic_auth.verify_password
def verify_password(username, password):
    try:
        user = User.query.filter_by(username = username).first()
        if not user or not user.verify_password(password):
            return False
        else:
            return True
    except:
       writeLog('[ERROR] SQL query failed (DB not initialized?)')
       return False

def writeLog(msg):

    '''
    Use logger() to write an event log
    '''

    ts = strftime('[%Y-%b-%d %H:%M]')
    logger.error('%s %s %s %s %s',
        ts,
        request.remote_addr,
        request.method,
        request.full_path,
        msg)

def appendImages(images):
    bgColor=(255,255,255)
    widths, heights = zip(*(i.size for i in images))

    new_width = max(widths)
    new_height = sum(heights)
    new_im = Image.new('RGB', (new_width, new_height), color = bgColor)
    offset = 0
    for im in images:
        # x = int((new_width - im.size[0])/2)
        x = 0
        new_im.paste(im, (x, offset))
        offset += im.size[1]
    return new_im

def extractEmail(string):
    match = re.match('.*\<(\S+)\>.*', string)
    if match:
        return match.group(1)
    else:
        return None

def processEml(data):

    '''
    Process the email (bytes), extract MIME parts and useful headers.
    Generate a PNG picture of the mail
    '''

    # Create the dump directory if not existing yet
    if not os.path.isdir(dumpDir):
        os.makedirs(dumpDir)
        writeLog("[INFO] Created dump directory %s" % dumpDir)

    msg = email.message_from_bytes(data)
    try:
        decode = email.header.decode_header(msg['Date'])[0]
        dateField = str(decode[0])
    except:
        dateField = '&lt;Unknown&gt;'
    writeLog('[INFO] Date: %s' % dateField)

    try:
        decode = email.header.decode_header(msg['From'])[0]
        fromField = str(decode[0])
    except:
        fromField = '&lt;Unknown&gt;'
    writeLog('[INFO] From: %s' %  fromField)
    fromField = fromField.replace('<', '&lt;').replace('>', '&gt;')

    try:
        decode = email.header.decode_header(msg['To'])[0]
        toField = str(decode[0])
    except:
        toField = '&lt;Unknown&gt;'
    writeLog('[INFO] To: %s' % toField)
    toField = toField.replace('<', '&lt;').replace('>', '&gt;')

    try:
        decode = email.header.decode_header(msg['Subject'])[0]
        subjectField = str(decode[0])
    except:
        subjectField = '&lt;Unknown&gt;'
    writeLog('[INFO] Subject: %s' % subjectField)
    subjectField = subjectField.replace('<', '&lt;').replace('>', '&gt;')

    try:
        decode = email.header.decode_header(msg['Message-Id'])[0]
        idField = str(decode[0])
    except:
        idField = '&lt;Unknown&gt;'
    writeLog('[INFO] Message-Id: %s' % idField)
    idField = idField.replace('<', '&lt;').replace('>', '&gt;')    

    imgkitOptions = { 'load-error-handling': 'skip'}
    # imgkitOptions.update({ 'quiet': None })
    imagesList = []
    attachments = []

    # Build a first image with basic mail details
    headers = '''
    <table width="100%%">
      <tr><td align="right"><b>Date:</b></td><td>%s</td></tr>
      <tr><td align="right"><b>From:</b></td><td>%s</td></tr>
      <tr><td align="right"><b>To:</b></td><td>%s</td></tr>
      <tr><td align="right"><b>Subject:</b></td><td>%s</td></tr>
      <tr><td align="right"><b>Message-Id:</b></td><td>%s</td></tr>
    </table>
    <hr></p>
    ''' % (dateField, fromField, toField, subjectField, idField)
    m = hashlib.md5()
    m.update(headers.encode('utf-8'))
    imagePath = m.hexdigest() + '.png'
    try:
        imgkit.from_string(headers, dumpDir + '/' + imagePath, options = imgkitOptions)
        writeLog('[INFO] Created headers %s' % imagePath)
        imagesList.append(dumpDir + '/' + imagePath)
    except:
        writeLog('[WARNING] Creation of headers failed')

    #
    # Main loop - process the MIME parts
    #
    for part in msg.walk():
        mimeType = part.get_content_type()
        if part.is_multipart():
            writeLog('[INFO] Multipart found, continue')
            continue

        writeLog('[INFO] Found MIME part: %s' % mimeType)
        if mimeType in textTypes:
            try:
                payload = quopri.decodestring(part.get_payload(decode=True)).decode('utf-8')
            except:
                payload = str(quopri.decodestring(part.get_payload(decode=True)))[2:-1]
            
            # Cleanup dirty characters
            dirtyChars = [ '\n', '\\n', '\t', '\\t', '\r', '\\r']
            for char in dirtyChars:
                payload = payload.replace(char, '')
            
            # Generate MD5 hash of the payload
            m = hashlib.md5()
            m.update(payload.encode('utf-8'))
            imagePath = m.hexdigest() + '.png'
            try:
                imgkit.from_string(payload, dumpDir + '/' + imagePath, options = imgkitOptions)
                writeLog('[INFO] Decoded %s' % imagePath)
                imagesList.append(dumpDir + '/' + imagePath)
            except:
                writeLog('[WARNING] Decoding this MIME part returned error')
        elif mimeType in imageTypes:
            payload = part.get_payload(decode=False)
            imgdata = base64.b64decode(payload)
            # Generate MD5 hash of the payload
            m = hashlib.md5()
            m.update(payload.encode('utf-8'))
            imagePath = m.hexdigest() + '.' + mimeType.split('/')[1]
            try:
                with open(dumpDir + '/' + imagePath, 'wb') as f:
                    f.write(imgdata)
                writeLog('[INFO] Decoded %s' % imagePath)
                imagesList.append(dumpDir + '/' + imagePath)
            except:
                writeLog('[WARNING] Decoding this MIME part returned error')
        else:
            fileName = part.get_filename()
            if not fileName:
                fileName = "Unknown"
            attachments.append("%s (%s)" % (fileName, mimeType))
            writeLog('[INFO] Skipped attachment %s (%s)' % (fileName, mimeType))

    if len(attachments):
        footer = '<p><hr><p><b>Attached Files:</b><p><ul>'
        for a in attachments:
            footer = footer + '<li>' + a + '</li>'
        footer = footer + '</ul><p><br>Generated by EMLRender v1.0'
        m = hashlib.md5()
        m.update(footer.encode('utf-8'))
        imagePath = m.hexdigest() + '.png'
        try:
            imgkit.from_string(footer, dumpDir + '/' + imagePath, options = imgkitOptions)
            writeLog('[INFO] Created footer %s' % imagePath)
            imagesList.append(dumpDir + '/' + imagePath)
        except:
            writeLog('[WARNING] Creation of footer failed')

    resultImage = dumpDir + '/' + 'new.png'
    if len(imagesList) > 0:
        images = list(map(Image.open, imagesList))
        combo = appendImages(images)
        combo.save(resultImage)
        # Clean up temporary images
        for i in imagesList:
           os.remove(i)
        return(resultImage)
    else:
        return(False)

class Upload(Resource):

    '''
    Handle the upload of an EML file.
    Supported files are flat files or ZIP archive (encrypted or not)
    The function supports the REST API or a classic form POST.
    '''

    @basic_auth.login_required
    def post(self):
        writeLog('[INFO] User %s successfully authenticated' % request.authorization.username)

        if 'file' not in request.files:
            return {"message": "No file found"}
        file = request.files['file']
        #
        # Support for ZIP files:
        #
        if zipfile.is_zipfile(file):
            writeLog('[INFO] Uploaded file is a zip archive')
            zpw = request.form.get('password')
            zfd = zipfile.ZipFile(file)
            zfile = zfd.namelist()[0]
            #
            # TODO: Support multiple files in the zip file, 
            # Now, only process the 1st one
            #
            try:
                if zpw:
                    writeLog('[INFO] Zip password provided: %s' % zpw)
                zbytes = zfd.read(zfile, pwd=bytes(zpw,'utf-8'))
            except:
                writeLog('[ERROR] Cannot unzip file: %s' % zfile)
                return Response(json.dumps([{"message": "Cannot process the ZIP file" % zfile}]), mimetype='application/json')
            image = processEml(zbytes)
        else:
            # This is a regular EML file
            # Bug? File has been read by ZipFile.read(), restart from byte 0!
            file.seek(0)
            image = processEml(file.read())

        if image:
            return send_file(image)
        else:
            return Response(json.dump([{"message": "Cannot process the EML file"}]), mimetype='application/json')

    def get(self):
        writeLog('[INFO] Upload page requested')

        return Response('''
        <!doctype html>
        <title>EMLRender: Upload new EML File</title>
        <h1>EMLRender</h1>
        Upload new File:
        <form method=post enctype=multipart/form-data>
        <p>
        EML File or ZIP Archive: <input type=file name=file></br>
        ZIP Password (optional): <input type=text name="password" size=20>
        <br>
        <input type=submit value=Upload>
        </form>
        ''', mimetype='text/html')

class Root(Resource):
    def get(self):
        writeLog('[INFO] Root page requested')

        return Response('''
        <!doctype html>
        <title>EMLRender</title>
        Please upload a file via <a href="/upload">/upload</a> or read the <a href="/help">/help</a>.
        ''', mimetype='text/html')

class Help(Resource):
    def get(self):
        writeLog('[INFO] Help page displayed')
        return Response('''
            <!doctype html>
            <title>EMLRender</title>
            <h1>EMLRender</h1>
            This web service renders email files submitted in EML[1] format. Files can be <a href="/upload">uploaded</a> with a browser or via a REST API interface. The output is a PNG image.</br>
            The EML File can be uploaded in a ZIP archive (with optional password).
            <p>
            The following commands are available:
            <ul>
            <li<GET /help</li>
            <li>POST /upload</li>
            <li>POST /init (Initialize the users database)</li>
            <li>POST /users/add (Create a user admin)</li>
            <li>POST /users/resetpw (Change a user's password)</li>
            <li>POST /users/delete (Remove a user account)</li>
            </ul>
            Examples of usage:
            <pre>$ curl -u user:password -F file=@"spam.eml" -o result.png http://server.domain.com/upload</pre>
            <pre>$ curl -u user:password -F file=@"malicious.zip" -F password=infected -o result.png http://server.domain.com/upload</pre>
            <pre>$ curl -u admin:password -X POST -d "{'username':'john'}" https://server.domain.com/users/add</pre>
            <p>
            [1] Used by many email clients including Novell GroupWise, Microsoft Outlook Express, Lotus notes, Windows Mail, Mozilla Thunderbird, and Postbox. EML files contain the email as plain text in MIME format, containing the email header and body, including attachments in one or more of several formats.
            ''', mimetype='text/html')

class Init(Resource):

    '''
    Generate the initial 'admin' account. 
    Creates a password and a token in the database without authentication.
    If the user 'admin' already exists returns an error

    Parameters:
    - password: The admin password to create
    '''

    def post(self):
        writeLog('[INFO] Init page requested')

        username = 'admin'
        if User.query.filter_by(username = username).first() is not None:
            writeLog('[ERROR] Users database already initialized')
            return Response(json.dumps([{ "message" : "The users database has already been initialized" }]), mimetype='application/json')

        # Generate a random 10 characters password
        m = hashlib.md5()
        m.update(''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10)).encode('utf-8'))
        password = m.hexdigest() 
        
        user  = User(username = username)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()

        writeLog('[INFO] Users database successfully initialized')
        return Response(json.dumps([{ "message" : "Users database successfully initialized" }]), mimetype='application/json')

class AddUser(Resource):

    '''
    Create a new user in the database (restricted to the 'admin' user)
    Note: if no password is provided, a random password is generated
    Example:
    $ curl -u admin:pass -X POST -d {'username':'foo','password':'bar'} https://127.0.0.1/users/add
    '''

    @basic_auth.login_required

    def post(self):
        writeLog('[INFO] AddUser page requested')

        # Restrict access to admin
        if request.authorization.username != 'admin':
            writeLog('[WARNING] Access denied')
            return Response(json.dumps([{ "message" : "Access denied" }]), mimetype='application/json')
        else:
            writeLog('[INFO] Admin authentication successful')

        # Use this to load JSON data event if the mimetype of not correctly set
        request_json = request.get_json(force=True)
        username = request_json.get('username')
        password = request_json.get('password')
        if username is None:
            writelog('[ERROR] Missing username parameter')
            return Response(json.dump([{ "message" : "Missing username parameter" }]), mimetype='application/json')

        if password is None:
            # Generate a random 10 characters password
            m = hashlib.md5()
            m.update(''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10)).encode('utf-8'))
            password = m.hexdigest() 

        if User.query.filter_by(username = username).first() is not None:
            writeLog('[ERROR] Users already exists: %s' % username)
            return Response(json.dumps([{ "message" : "User already exists" }]), mimetype='application/json')

        user  = User(username = username)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()

        writeLog('[INFO] Account %s successfully created' % username)
        return Response(json.dumps([{ "message" : "Account successfully created", "username" : username, "password" : password }]), mimetype='application/json')

class ResetPw(Resource):

    '''
    Reset a user's password
    Note: if no password is provided, a random password is generated
    Example:
    $ curl -u admin:pass -X POST -d '{"username":"user", "newpassword":"setcretpw"}'' https://127.0.0.1/users/add
    '''

    @basic_auth.login_required

    def post(self):
        writeLog('[INFO] ResetPw page requested')

        isAdmin = False

        # Are we admin? Only the admin can change any password
        if request.authorization.username == 'admin':
            isAdmin = True
            writeLog('[INFO] Admin successfully authenticated')
        else:
            writeLog('[INFO] User %s successfully authenticated' % request.authorization.username)

        # Use this to load JSON data event if the mimetype of not correctly set
        request_json = request.get_json(force=True)
        username = request_json.get('username')
        newpassword = request_json.get('newpassword')
        if username is None:
            writelog('[ERROR] Missing username parameter')
            return Response(json.dumps([{ "message" : "Missing username parameter" }]), mimetype='application/json')

        if username == 'admin' and isAdmin == False:
            writeLog('[ERROR] Admin password change rejected')
            return Response(json.dumps([{ "message" : "Access denied" }]), mimetype='application/json')

        if newpassword is None:
            # Generate a random 10 characters password
            m = hashlib.md5()
            m.update(''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10)).encode('utf-8'))
            newpassword = m.hexdigest() 

        if User.query.filter_by(username = username).first() is None:
            writeLog('[ERROR] Users %s do not exist: %s' % username)
            return Response(json.dumps([{ "message" : "User do not exist" }]), mimetype='application/json')
       
        user  = User(username = username)
        user.hash_password(newpassword)
        db.session.commit()

        writeLog('[INFO] Password successfully updated: %s' % username)
        return Response(json.dumps([{ "message" : "Password successfully updated", "username" : username, "password" : newpassword }]), mimetype='application/json')

class DeleteUser(Resource):

    '''
    Delete  a user account
    Only allowed to admin
    Example:
    $ curl -u admin:pass -X POST -d '{"username":"user"}' https://127.0.0.1/users/delete
    '''

    @basic_auth.login_required

    def post(self):
        writeLog('[INFO] DeleteUser page requested')

        # Only admin can remove an account
        if request.authorization.username != 'admin':
            writeLog('[ERROR] Access denied')
            return Response(json.dumps([{ "message" : "Access denied" }]), mimetype='application/json')

        # Use this to load JSON data event if the mimetype of not correctly set
        request_json = request.get_json(force=True)
        username = request_json.get('username')
        if username is None:
            writelog('[ERROR] Missing username parameter')
            return Response(json.dumps([{ "message" : "Missing username parameter" }]), mimetype='application/json')

        if username == 'admin':
            writeLog('[ERROR] Admin account cannott be deleted')
            return Response(json.dumps([{ "message" : "Account cannot be deleted" }]), mimetype='application/json')

        if User.query.filter_by(username = username).first() is None:
            writeLog('[ERROR] Account %s do not exist: %s' % username)
            return Response(json.dumps([{ "message" : "Account do not exist" }]), mimetype='application/json')

        User.query.filter_by(username = username).delete()
        db.session.commit()

        writeLog('[INFO] Account %s  successfully deleted' % username)
        return Response(json.dumps([{ "message" : "Account successfully deleted" }]), mimetype='application/json')

class ListUsers(Resource):

    '''
    List accounts (Only allowed to admin)
    Example:
    $ curl -u admin:pass https://127.0.0.1/users/list
    '''

    @basic_auth.login_required

    def get(self):
        writeLog('[INFO] ListUsers page requested')

        # Only admin can list accounts
        if request.authorization.username != 'admin':
            writeLog('[ERROR] Access denied')
            return Response(json.dumps([{ "message" : "Access denied" }]), mimetype='application/json')

        jsondata = [{ "message" : "Success" }]
        users = User.query.all()
        for user in users:
            jsondata.append({"username" : user.username})

        writeLog('[INFO] Accounts list successfully returned')
        return Response(json.dumps(jsondata),  mimetype='application/json')

def main():
    global logger

    # Create the initial database
    db.create_all()

    api.add_resource(Root, '/')
    api.add_resource(Upload, '/upload')
    api.add_resource(Help, '/help')
    api.add_resource(Init, '/init')
    api.add_resource(ListUsers, '/users/list')
    api.add_resource(AddUser, '/users/add')
    api.add_resource(DeleteUser, '/users/delete')
    api.add_resource(ResetPw, '/users/resetpw')
    handler = RotatingFileHandler('api.log', maxBytes=50000, backupCount=5)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.ERROR)
    logger.addHandler(handler)
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')

if __name__ == 'EMLRender':
    main()
    sys.exit(0)
