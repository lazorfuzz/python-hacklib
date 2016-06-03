# hacklib
![MIT License](https://img.shields.io/github/license/mashape/apistatus.svg)
[![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/)
##### Toolkit for hacking enthusiasts using Python.
hacklib is a Python module for hacking enthusiasts. It is currently in its barebones stages.

#### Examples of Usage
-
Multi-threaded Denial of Service (DOS) Stress-Testing:
```python
import hacklib

dos = hacklib.DOSer()
dos.launch('yourwebsite.com', duration=30, threads=50)
```
-
Port Scanning:
```python
from hacklib import *

ps = PortScanner()
ps.scan(getIP('yourwebsite.com'))

# After a scan, open ports are saved within ps for reference
if ps.portOpen(80):
    # Establishes a TCP stream and sends a message
    send(getIP('yourwebsite.com'), 80, message='GET HTTP/1.1 \r\n')
```
-
Universal Login for almost all HTTP/HTTPS login pages:

```python
import hacklib

# AuthClient uses the mechanize module for form-based logins. 
ac = hacklib.AuthClient()
# Attempts to login and return the HTML of the resulting page.
# Returns False if login fails on HTML Basic Authentication
htmldata = ac.login('http://yourwebsite.com', 'username', 'password')
if 'incorrect' not in htmldata:
    print 'Login Success'
```
