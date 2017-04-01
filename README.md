# Nuki client for Python 3

This python library let's you talk with the Nuki smart lock (https://nuki.io/)

## Get started

### 1. Hardware
Install a BLE-compatible USB dongle (or use the built-in bluetooth stack if available)

### 2. Install dependencies
```
$ sudo apt install libffi-dev pkg-config libboost-python-dev libboost-thread-dev libbluetooth-dev libglib2.0-dev python3-dev bluetooth libbluetooth-dev
```

### 3. Install bluez
You'll get more infos [here](https://learn.adafruit.com/install-bluez-on-the-raspberry-pi/installation)

### 4. Some hacks
Replace the `/usr/local/lib/python3.[YOUR-PY-VERSION]/dist-packages/pygatt/backends/gatttool/gatttool.py` file with the file from this repository.

### 5. Install Nuki Client
```
$ sudo pip install python-nuki-client
```

### That's all!
You are now ready to use the library in python!

## Example usage
### Authenticate
Before you will be able to send commands to the Nuki lock using the library, you must first authenticate (once!) yourself with a self-generated public/private keypair (using NaCl):

```python
from nukiclient import Nuki
from nacl.public import PrivateKey
import binascii

nuki_mac_address = "00:00:00:00:00:01"
# generate the private key which must be kept secret
key_pair = PrivateKey.generate()
public_key_hex = binascii.hexlify(key_pair.public_key.encode())
private_key_hex = binascii.hexlify(key_pair.encode())
id = 50
# id-type = 00 (app), 01 (bridge) or 02 (fob)
# take 01 (bridge) if you want to make sure that the 'new state available'-flag is cleared on the Nuki if you read it out the state using this library
id_type = '01'
name = "PiBridge"

nuki = Nuki(nuki_mac_address)
nuki.authenticate_user(public_key_hex, private_key_hex, id, id_type, name)
```

**REMARK 1** The credentials are stored in the file (hard-coded for the moment in nuki.py) : ./nuki.cfg

**REMARK 2** Authenticating is only possible if the lock is in 'pairing mode'. You can set it to this mode by pressing the button on the lock for 5 seconds until the complete LED ring starts to shine.

**REMARK 3** You can find out your Nuki's MAC address by using 'hcitool lescan' for example.

### Commands to the Nuki KT
Once you are authenticated (and the nuki.cfg file is created on your system), you can use the library to send command to your Nuki lock:

```python
from nukiclient import Nuki

nuki_mac_address = "00:00:00:00:00:01"
pin = 0000

nuki = Nuki(nuki_mac_address)

# Reads the lock state
nuki.read_lock_state()

# Performs an action
nuki.lock_action("UNLOCK")

# Gets log entries
logs = nuki.get_log_entries(10, pin)
print("received {} log entries".format(len(logs)))

# Requests calibration
nuki.request_calibration(pin)

# Checks if a new state is available
available = nuki.is_new_nuki_state_available()
print("New state available: {}".format(available))
```

**REMARK** the method `is_new_nuki_state_available()` only works if you run your python script as root (sudo). All the other methods do not require root privileges
