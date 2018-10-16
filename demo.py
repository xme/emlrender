# this file is a demo file to interact with the emlrender API.
# adjust the username, password, request_url and the file you want to send to it.
# output will be saved as output.png


import requests
from requests.auth import HTTPBasicAuth

username = "admin"
password = "strongpw"

request_url = "https://127.0.0.1/upload"

# In this example, I'm passing some data along with the request.
# these are generally what you would expect to pass along in an encoded url:
# /api?some_url_param_key=some_url_param_value

data = {}

file = open('test_sample_message.eml','rb')


files={'file': file}
data["some_url_param_key"] = "some_url_param_value"

# This is an example header, not necessarily what you need,
# but it should serve as a good starting point.

headers = {}
headers["Accept"] = "*/*"

# You can use post() in some cases where you would expect to use get().
# Every API is its own unique snowflake and expects different inputs.
# Try opening up the Chrome console and run the request in the
# browser, where you know it works. Examine the headers and response
# in cases where the API you're accessing doesn't provide you
# with the necessary inputs.

result = requests.post(request_url, headers=headers,files=files,data=data,auth=HTTPBasicAuth(username, password), verify=False)

if result.status_code == 200:
    with open("output.png", 'wb') as f:
        f.write(result.content)
