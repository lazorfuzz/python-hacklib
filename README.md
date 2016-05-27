# hacklib
Toolkit for hacking enthusiasts using Python.<br>

hacklib is an all-in-one module for hacking enthusiasts. It is currently in its barebones stages.

Examples of Usage:

Multi-threaded Denial of Service (DOS) Stress-Testing:
```python
import hacklib

dos = hacklib.DOSer()
dos.launch('yourwebsite.com', duration=30, threads=50)
```
-
Port Scanning:
```python
import hacklib

ps = hacklib.PortScanner()
ps.scan(hacklib.getIP('google.com'))
```
-
Bonus "Security Cam Hack" (Not really):

```python
import hacklib

camera = hacklib.CamHacker(auth_key='majorkey')
camera.hack()
