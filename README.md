# Nuki client for Python 3

This python library let's you talk with Nuki lock (https://nuki.io/en/)

## Get started

### 1. Hardware
Install a BLE-compatible USB dongle (or use the built-in bluetooth stack if available)

### 2. Install libffi
`$ sudo apt-get install libffi-dev`

### 3. Install bluez
You'll get more infos [here](https://learn.adafruit.com/install-bluez-on-the-raspberry-pi/installation)

### 4. Install pygatt
`$ pip3 install pygatt`

### 5. Some hacks
Replace the `/usr/local/lib/python2.7/dist-packages/pygatt/backends/gatttool/gatttool.py` file with the file from this repository.

### 6. Install nacl
`$ pip3 install pynacl`

### 7. Install crc16
`$ pip3 install crc16`

### 8. Install Bluetooth
`$ sudo apt install bluetooth libbluetooth-dev`

### 9. Install pybluez
`$ pip3 install pybluez`

### 10. Install pexpect
`$ pip3 install pexpect`

### That's all!
You are now ready to use the library in python!

## Example usage
### Authenticate
Before you will be able to send commands to the Nuki lock using the library, you must first authenticate (once!) yourself with a self-generated public/private keypair (using NaCl):

```python
import nuki_messages
import nuki as _nuki
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

nuki = _nuki.Nuki(nuki_mac_address)
nuki.authenticate_user(public_key_hex, private_key_hex, id, id_type, name)
```

**REMARK 1** The credentials are stored in the file (hard-coded for the moment in nuki.py) : /home/pi/nuki/nuki.cfg

**REMARK 2** Authenticating is only possible if the lock is in 'pairing mode'. You can set it to this mode by pressing the button on the lock for 5 seconds until the complete LED ring starts to shine.

**REMARK 3** You can find out your Nuki's MAC address by using 'hcitool lescan' for example.

### Commands to the Nuki KT
Once you are authenticated (and the nuki.cfg file is created on your system), you can use the library to send command to your Nuki lock:

```python
import nuki_messages
import nuki as _nuki

nuki_mac_address = "00:00:00:00:00:01"
pin = 0000

nuki = _nuki.Nuki(nuki_mac_address)

# Reads the lock state
nuki.read_lock_state()

# Performs an action
nuki.lock_action("UNLOCK")

# Gets log entries
logs = nuki.get_log_entries(10, pin)
print("received {} log entries".format(len(logs)))

# Checks if a new state is available
available = nuki.is_new_nuki_state_available()
print("New state available: {}".format(available))
```

**REMARK** the method `is_new_nuki_state_available()` only works if you run your python script as root (sudo). All the other methods do not require root privileges
