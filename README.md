# EMLRender
## Introduction
Sometimes, while investigating incident implying emails, you can get a copy of the original message in [EML](http://www.forensicswiki.org/wiki/EML) format. Reading an EML file is not easy with all the SMTP headers and the mulitple MIME parts it may contain. But it may also contain suspicious code that is dangerous to be executed from sensitive environments. EMLRender is a Python script that provides a REST API to render submitted EML files into PNG images. This way, it's easy to have a clear overview of the mail content.

Here is a sample of generated image:
![alt text](https://raw.githubusercontent.com/xme/emlrender/master/sample.png "Sample image")

## Compoments
EMLRender is based on the [wkhtmltoimage](https://wkhtmltopdf.org/) tool to render HTML code. It consists of a single Python script that provides an HTTP interface or REST API. The best way to use it is to run it in a Docker container. This way, it can be easily deployed.

## Installation
### Building the  container
Use the provide Dockerfile to build your image:
```
$ git clone https://github.com/xme/emlrender
$ cd emlrender
$ docker build -t emlrender:latest .
```
An image is ready to use on hub.docker.com: [https://hub.docker.com/r/rootshell/emlrender/](https://hub.docker.com/r/rootshell/emlrender/)

### Starting the container
EMLRender is a stand-alone container that does not have any dependency.
```
$ docker run rootshell/emlrender:latest
```
Once started, it will listing to port 443. 
Note: a self-signed certificate is generated when the container is created.

## Setup & Configuration
### User database creation
EMLRender requires user authentication to render EML files. The first action is to generate the users database and an admin account:
```
$ curl -k -X POST -d '{"password":"strongpw"}' https://127.0.0.1/init
[{"message": "Users database successfully initialized"}, {"password": "strongpw"}]
```
If you don't specify a password, a random one will be generated:
```
$ curl -k -X POST -d '{}' https://127.0.0.1/init
[{"message": "Users database successfully initialized"}, {"password": "1o03uqjm6w"}]
```

### User accounts management
#### Creation
New users can be added with the following request:
```
$ curl -k -u admin:secretpw -X POST -d '{"username":"john", "password":"strongpw"}' https://127.0.0.1/users/add
[{"message": "Account successfully created", "username": "john", "password": "strongpw"}]
```
Note: If no password is provided, a random one will be generated.

#### Password change
Account passwords can be changed with the following request:
```
$ curl -k -u admin:secretpw -X POST -d '{"username":"john", "newpassword":"verystrongpw"}' https://127.0.0.1/users/resetpw
[{"message": "Password successfully updated", "username": "john", newpassword": "verystrongpw"}]
```
Note: Regular users can change their own password.

#### Deletion
Users can be deleted with the following request:
```
$ curl -k -u admin:secretpw -X POST -d '{"username":"john"}' https://127.0.0.1/users/delete
[{ "message" : "Account successfully deleted" }]
```

### Users listing
A list of users can be fetched with the following request:
```
$ curl -k -u admin:secretpw https://127.0.0.1/users/list
[{"message": "Success"}, {"username": "admin"}, {"username": "john"}]
```

## Usage
### Help page
A simple help page is available when you point your browser to the following URL: https://127.0.0.1/help

### EML Rendering
#### REST API
To submit an EML file, use the following request:
```
$ curl -k -u john:strongpw -F file=@"spam.eml" -o spam.png https://127.0.0.1/upload
```
The generated picture will be saved into spam.png.
It is possible to submit a ZIP archive containing the EML file (encrypted archives are supported):
```
$ curl -k -u john:strongpw -F file=@"malicious.zip" -F password=infected -o malicious.png https://127.0.0.1/upload
```

#### Web browser
Point your browser to https://127.0.0.1/upload to submit your EML file via a normal HTML form.

## Logging
### HTTP log
A classic HTTP log is available via the Docker interface:
```
$ docker logs -f emlrender
 * Running on https://0.0.0.0:443/ (Press CTRL+C to quit)
172.17.0.1 - - [18/May/2018 11:59:43] "POST /init HTTP/1.1" 200 -
172.17.0.1 - - [18/May/2018 12:06:36] "POST /users/add HTTP/1.1" 200 -
172.17.0.1 - - [18/May/2018 12:12:08] "GET /users/list HTTP/1.1" 200 -
```

The application log is available via the api.log file in the container:
```
$ docker exec -it emlrender tail -f api.log
[2018-May-18 11:59] 172.17.0.1 POST /init? [INFO] Init page requested
[2018-May-18 11:59] 172.17.0.1 POST /init? [INFO] Users database successfully initialized
[2018-May-18 12:06] 172.17.0.1 POST /users/add? [INFO] AddUser page requested
[2018-May-18 12:06] 172.17.0.1 POST /users/add? [INFO] Admin authentication successful
[2018-May-18 12:06] 172.17.0.1 POST /users/add? [INFO] Account john successfully created
[2018-May-18 12:12] 172.17.0.1 GET /users/list? [INFO] ListUsers page requested
[2018-May-18 12:12] 172.17.0.1 GET /users/list? [INFO] Accounts list successfully returned
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] User john successfully authenticated
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] Date: Fri, 18 May 2018 10:38:26 +0200
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] From: <redacted>
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] To: <redacted>
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] Subject: <redacted>
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] Message-Id: <redacted>
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] Created headers 6346209b0e191fe5e9a740db4e7a2db6.png
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] Multipart found, continue
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] Found MIME part: text/plain
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] Decoded 693d8cdec2a72278157ac4bb107b44b0.png
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] Found MIME part: text/html
[2018-May-18 12:24] 172.17.0.1 POST /upload? [INFO] Decoded 461c46fefa1b887857398ba17446b822.png
```


