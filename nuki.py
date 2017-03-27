import nacl.utils
import pygatt.backends
import array
from nacl.public import PrivateKey, Box
from byteswap import ByteSwapper
from crc import CrcCalculator
import nuki_messages
import sys
import configparser
import blescan
import bluetooth._bluetooth as bluez
from utils import *


class Nuki(): 
  def __init__(self, mac_address):
    """
    Creates a BLE connection with your Nuki KT.
    :param mac_address: The MAC address of the KT.
    """
    self._char_write_response = ""
    self.parser = nuki_messages.CommandParser()
    self.crc_calculator = CrcCalculator()
    self.byte_swapper = ByteSwapper()
    self.mac_address = mac_address
    self.config = configparser.RawConfigParser()
    self.config.read('./nuki.cfg')
    self.device = None


  def _make_ble_connection(self):
    """
    Establishes the BLE connection to the KT.
    Private method.
    """
    if self.device is None:
      adapter = pygatt.backends.GATTToolBackend()
      nuki_ble_connection_ready = False

      while nuki_ble_connection_ready:
        print("Starting BLE adapter...")
        adapter.start()
        print("Init Nuki BLE connection...")
        try :
          self.device = adapter.connect(self.mac_address)
          nuki_ble_connection_ready = True
        except:
          print("Unable to connect, retrying...")

      print("Nuki BLE connection established")
  

  def is_new_nuki_state_available(self):
    """
    Checks if a new KT state is available.
    Only works if script is running as root.
    """
    if self.device != None:
      self.device.disconnect()
      self.device = None
      
    dev_id = 0
    try:
      sock = bluez.hci_open_dev(dev_id)
    except:
      print("error accessing bluetooth device...")
      sys.exit(1)
    blescan.hci_le_set_scan_parameters(sock)
    blescan.hci_enable_le_scan(sock)
    returned_list = blescan.parse_events(sock, 10)
    new_state_available = -1
    for beacon in returned_list:
      beacon_elements = beacon.split(',')
      if beacon_elements[0] == self.mac_address and beacon_elements[1] == "a92ee200550111e4916c0800200c9a66":
        if beacon_elements[4] == '-60':
          new_state_available = 0
        else:
          new_state_available = 1
        break
    return new_state_available
  

  def _handle_char_write_response(self, handle, value):
    """
    Handles the responses from the KT.
    Private method.
    """
    self._char_write_response += "".join(format(x, '02x') for x in value)
  
  
  def authenticate_user(self, public_key_hex, private_key_hex, id, id_type, name):
    """
    Authorizes a new user. The KT has to be in inclusion mode for this process.
    Press and hold the button on the KT for 5 seconds until the light is on.

    :param public_key_hex: The public key which should be authorized.
    :param private_key_hex: The private key which belongs to the public key.
    :param id: A unique identifier to identify the user.
    :param id_type: The type of the user. ('00' => 'app', '01' => 'bridge', '02' => 'fob')
    :param name: The display name for this user. (Appears in the logs)
    """
    self._make_ble_connection()

    self.config.remove_section(self.mac_address)
    self.config.add_section(self.mac_address)

    pairing_handle = self.device.get_handle('a92ee101-5501-11e4-916c-0800200c9a66')
    print("Nuki Pairing UUid handle created: %04x" % pairing_handle)

    public_key_req = nuki_messages.Request('0003')
    self.device.subscribe('a92ee101-5501-11e4-916c-0800200c9a66', self._handle_char_write_response)

    public_key_reqCommand = public_key_req.generate()

    self._char_write_response = ""

    print("Requesting Nuki Public Key using command: %s" % public_key_req.show())
    self.device.char_write_handle(pairing_handle,public_key_reqCommand,True,2)
    print("Nuki Public key requested")

    command_parsed = self.parser.parse(self._char_write_response)

    if self.parser.isNukiCommand(self._char_write_response) == False:
      sys.exit("Error while requesting public key: %s" % command_parsed)

    if command_parsed.command != '0003':
      sys.exit("Nuki returned unexpected response (expecting PUBLIC_KEY): %s" % command_parsed.show())

    public_key_nuki = command_parsed.publicKey

    self.config.set(self.mac_address, 'publicKeyNuki', to_str(public_key_nuki))
    self.config.set(self.mac_address, 'publicKeyHex', to_str(public_key_hex))
    self.config.set(self.mac_address, 'privateKeyHex', to_str(private_key_hex))
    self.config.set(self.mac_address, 'ID', to_str(id))
    self.config.set(self.mac_address, 'IDType', to_str(id_type))
    self.config.set(self.mac_address, 'name', to_str(name))

    print("Public key received: %s" % command_parsed.publicKey)
    public_key_push = nuki_messages.PublicKey(public_key_hex)
    public_key_push_command = public_key_push.generate()
    print("Pushing Public Key using command: %s" % public_key_push.show())

    self._char_write_response = ""

    self.device.char_write_handle(pairing_handle,public_key_push_command,True,5)
    print("Public key pushed")

    command_parsed = self.parser.parse(self._char_write_response)

    if self.parser.isNukiCommand(self._char_write_response) == False:
      sys.exit("Error while pushing public key: %s" % command_parsed)

    if command_parsed.command != '0004':
      sys.exit("Nuki returned unexpected response (expecting CHALLENGE): %s" % command_parsed.show())

    print("Challenge received: %s" % command_parsed.nonce)
    nonce_nuki = command_parsed.nonce

    auth_authenticator = nuki_messages.AuthAuthenticator()
    auth_authenticator.createPayload(nonce_nuki, private_key_hex, public_key_hex, public_key_nuki)
    auth_authenticator_command = auth_authenticator.generate()

    self._char_write_response = ""

    self.device.char_write_handle(pairing_handle,auth_authenticator_command,True,5)
    print("Authorization Authenticator sent: %s" % auth_authenticator.show()) 

    command_parsed = self.parser.parse(self._char_write_response)

    if self.parser.isNukiCommand(self._char_write_response) == False:
      sys.exit("Error while sending Authorization Authenticator: %s" % command_parsed)

    if command_parsed.command != '0004':
      sys.exit("Nuki returned unexpected response (expecting CHALLENGE): %s" % command_parsed.show())

    print("Challenge received: %s" % command_parsed.nonce)
    nonce_nuki = command_parsed.nonce

    auth_data = nuki_messages.AuthData()
    auth_data.createPayload(public_key_nuki, private_key_hex, public_key_hex, nonce_nuki, id, id_type, name)
    auth_data_command = auth_data.generate()

    self._char_write_response = ""

    self.device.char_write_handle(pairing_handle,auth_data_command,True,7)
    print("Authorization Data sent: %s" % auth_data.show())

    command_parsed = self.parser.parse(self._char_write_response)

    if self.parser.isNukiCommand(self._char_write_response) == False:
      sys.exit("Error while sending Authorization Data: %s" % command_parsed)

    if command_parsed.command != '0007':
      sys.exit("Nuki returned unexpected response (expecting AUTH_ID): %s" % command_parsed.show())

    print("Authorization id received: %s" % command_parsed.show())
    nonce_nuki = command_parsed.nonce

    authorization_id = command_parsed.authID
    self.config.set(self.mac_address, 'authorizationID', to_str(authorization_id))

    authid = int(command_parsed.authID, 16)
    authid_confirm = nuki_messages.AuthIDConfirm()
    authid_confirm.createPayload(public_key_nuki, private_key_hex, public_key_hex, nonce_nuki, authid)
    authid_confirm_command = authid_confirm.generate()

    self._char_write_response = ""

    self.device.char_write_handle(pairing_handle,authid_confirm_command,True,7)
    print("Authorization id Confirmation sent: %s" % authid_confirm.show())

    command_parsed = self.parser.parse(self._char_write_response)

    if self.parser.isNukiCommand(self._char_write_response) == False:
      sys.exit("Error while sending Authorization id Confirmation: %s" % command_parsed)

    if command_parsed.command != '000E':
      sys.exit("Nuki returned unexpected response (expecting STATUS): %s" % command_parsed.show())

    print("STATUS received: %s" % command_parsed.status)

    with open('./nuki.cfg', 'at') as configfile:
      self.config.write(configfile)
    return command_parsed.status
  

  def read_lock_state(self):
    """
    Reads the current lock state from the KT.
    """
    self._make_ble_connection()
    key_turner_usd_io_handle = self.device.get_handle("a92ee202-5501-11e4-916c-0800200c9a66")
    self.device.subscribe('a92ee202-5501-11e4-916c-0800200c9a66', self._handle_char_write_response)

    state_req = nuki_messages.Request(payload='000C')
    state_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=state_req, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    state_req_encrypted_command = state_req_encrypted.generate()

    self._char_write_response = ""
    self.device.char_write_handle(key_turner_usd_io_handle,state_req_encrypted_command,True,3)

    print("Nuki State Request sent: %s\nresponse received: %s" % (state_req.show(),self._char_write_response)) 

    command_parsed = self.parser.decrypt(self._char_write_response,self.config.get(self.mac_address, 'publicKeyNuki'),self.config.get(self.mac_address, 'privateKeyHex'))[8:]

    if self.parser.isNukiCommand(command_parsed) == False:
      sys.exit("Error while requesting Nuki STATES: %s" % command_parsed)

    command_parsed = self.parser.parse(command_parsed)

    if command_parsed.command != '000C':
      sys.exit("Nuki returned unexpected response (expecting Nuki STATES): %s" % command_parsed.show())

    print(command_parsed.show())
    return command_parsed
    

  def lock_action(self, lock_action):
    """
    Performs a lock action at the KT.

    :param lock_action: The lock action to perform.

    Actions:
      * UNLOCK
      * LOCK
      * UNLATCH
      * LOCKNGO
      * LOCKNGO_UNLATCH
      * FOB_ACTION_1
      * FOB_ACTION_2
      * FOB_ACTION_3
    """
    self._make_ble_connection()
    key_turner_usd_io_handle = self.device.get_handle("a92ee202-5501-11e4-916c-0800200c9a66")
    self.device.subscribe('a92ee202-5501-11e4-916c-0800200c9a66', self._handle_char_write_response)

    challenge_req = nuki_messages.Request('0004')
    challenge_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=challenge_req, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    challenge_req_encrypted_command = challenge_req_encrypted.generate()

    self._char_write_response = ""
    self.device.char_write_handle(key_turner_usd_io_handle,challenge_req_encrypted_command,True,4)

    print("Nuki CHALLENGE Request sent: %s" % challenge_req.show()) 

    command_parsed = self.parser.decrypt(self._char_write_response,self.config.get(self.mac_address, 'publicKeyNuki'),self.config.get(self.mac_address, 'privateKeyHex'))[8:]

    if self.parser.isNukiCommand(command_parsed) == False:
      sys.exit("Error while requesting Nuki CHALLENGE: %s" % command_parsed)

    command_parsed = self.parser.parse(command_parsed)

    if command_parsed.command != '0004':
      sys.exit("Nuki returned unexpected response (expecting Nuki CHALLENGE): %s" % command_parsed.show())

    print("Challenge received: %s" % command_parsed.nonce)

    lock_action_req = nuki_messages.LockAction()
    lock_action_req.createPayload(self.config.getint(self.mac_address, 'ID'), lock_action, command_parsed.nonce)
    lock_action_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=lock_action_req, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    lock_action_req_encrypted_command = lock_action_req_encrypted.generate()

    self._char_write_response = ""

    self.device.char_write_handle(key_turner_usd_io_handle,lock_action_req_encrypted_command,True,4)

    print("Nuki Lock Action Request sent: %s" % lock_action_req.show()) 

    command_parsed = self.parser.decrypt(self._char_write_response,self.config.get(self.mac_address, 'publicKeyNuki'),self.config.get(self.mac_address, 'privateKeyHex'))[8:]

    if self.parser.isNukiCommand(command_parsed) == False:
      sys.exit("Error while requesting Nuki Lock Action: %s" % command_parsed)

    command_parsed = self.parser.parse(command_parsed)

    if command_parsed.command != '000C' and command_parsed.command != '000E':
      sys.exit("Nuki returned unexpected response (expecting Nuki STATUS/STATES): %s" % command_parsed.show())

    print(command_parsed.show())


  def request_calibration(self, pin=0000):
    """
    Requests calibration of the KT.

    :param pin: The 2-byte PIN code set at the KT. (Default: 0000)
    """
    pin_hex = '%04x' % pin

    self._make_ble_connection()
    key_turner_usd_io_handle = self.device.get_handle("a92ee202-5501-11e4-916c-0800200c9a66")
    self.device.subscribe('a92ee202-5501-11e4-916c-0800200c9a66', self._handle_char_write_response)

    challenge_req = nuki_messages.Request('0004')
    challenge_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=challenge_req, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    challenge_req_encrypted_command = challenge_req_encrypted.generate()

    self._char_write_response = ""

    print("Requesting CHALLENGE: %s" % challenge_req_encrypted.generate("HEX"))
    self.device.char_write_handle(key_turner_usd_io_handle, challenge_req_encrypted_command, True, 5)
    print("Nuki CHALLENGE Request sent: %s" % challenge_req.show())

    command_parsed = self.parser.decrypt(self._char_write_response,self.config.get(self.mac_address, 'publicKeyNuki'),self.config.get(self.mac_address, 'privateKeyHex'))[8:]

    if self.parser.isNukiCommand(command_parsed) == False:
      sys.exit("Error while requesting Nuki CHALLENGE: %s" % command_parsed)

    command_parsed = self.parser.parse(command_parsed)

    if command_parsed.command != '0004':
      sys.exit("Nuki returned unexpected response (expecting Nuki CHALLENGE): %s" % command_parsed.show())

    print("Challenge received: %s" % command_parsed.nonce)

    calibration_req = nuki_messages.CalibrationRequest()
    calibration_req.create_payload(command_parsed.nonce, self.byte_swapper.swap(pin_hex))
    calibration_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=calibration_req, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    calibration_req_encrypted_command = calibration_req_encrypted.generate()

    self._char_write_response = ""

    self.device.char_write_handle(key_turner_usd_io_handle, calibration_req_encrypted_command, True, 5)
    print("Nuki Calibration Request sent: %s" % calibration_req.show())

    command_parsed = self.parser.decrypt(self._char_write_response, self.config.get(self.mac_address, 'publicKeyNuki'), self.config.get(self.mac_address, 'privateKeyHex'))[8:]

    print(command_parsed)
    return command_parsed


  def get_log_entries_count(self, pin=0000):
    """
    Fetches the count of the log entries at the KT.

    :param pin: The 2-byte PIN code set at the KT. (Default: 0000)
    """
    pin_hex = '%04x' % pin

    self._make_ble_connection()
    key_turner_usd_io_handle = self.device.get_handle("a92ee202-5501-11e4-916c-0800200c9a66")
    self.device.subscribe('a92ee202-5501-11e4-916c-0800200c9a66', self._handle_char_write_response)

    challenge_req = nuki_messages.Request('0004')
    challenge_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=challenge_req, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    challenge_req_encrypted_command = challenge_req_encrypted.generate()

    self._char_write_response = ""

    print("Requesting CHALLENGE: %s" % challenge_req_encrypted.generate("HEX"))
    self.device.char_write_handle(key_turner_usd_io_handle,challenge_req_encrypted_command,True,5)
    print("Nuki CHALLENGE Request sent: %s" % challenge_req.show())

    command_parsed = self.parser.decrypt(self._char_write_response,self.config.get(self.mac_address, 'publicKeyNuki'),self.config.get(self.mac_address, 'privateKeyHex'))[8:]

    if self.parser.isNukiCommand(command_parsed) == False:
      sys.exit("Error while requesting Nuki CHALLENGE: %s" % command_parsed)

    command_parsed = self.parser.parse(command_parsed)

    if command_parsed.command != '0004':
      sys.exit("Nuki returned unexpected response (expecting Nuki CHALLENGE): %s" % command_parsed.show())

    print("Challenge received: %s" % command_parsed.nonce)

    log_entries_req = nuki_messages.LogEntriesRequest()
    log_entries_req.createPayload(0, command_parsed.nonce, self.byte_swapper.swap(pin_hex))
    log_entries_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=log_entries_req, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    log_entries_req_encrypted_command = log_entries_req_encrypted.generate()

    self._char_write_response = ""

    self.device.char_write_handle(key_turner_usd_io_handle,log_entries_req_encrypted_command,True,4)
    print("Nuki Log Entries Request sent: %s" % log_entries_req.show())

    command_parsed = self.parser.decrypt(self._char_write_response,self.config.get(self.mac_address, 'publicKeyNuki'),self.config.get(self.mac_address, 'privateKeyHex'))[8:]

    if self.parser.isNukiCommand(command_parsed) == False:
      sys.exit("Error while requesting Nuki Log Entries: %s" % command_parsed)

    command_parsed = self.parser.parse(command_parsed)

    if command_parsed.command != '0026':
      sys.exit("Nuki returned unexpected response (expecting Nuki LOG ENTRY): %s" % command_parsed.show())

    print(command_parsed.show())
    return int(command_parsed.logCount, 16)
  

  def get_log_entries(self, count, pin=0000):
    """
    Fetches log entries form the KT.
    Starts with the most recent one.

    :param count: The number of entries which should be fetched.
    :param pin: The 2-byte PIN code set at the KT. (Default: 0000)
    """
    pin_hex = '%04x' % pin

    self._make_ble_connection()
    key_turner_usd_io_handle = self.device.get_handle("a92ee202-5501-11e4-916c-0800200c9a66")
    self.device.subscribe('a92ee202-5501-11e4-916c-0800200c9a66', self._handle_char_write_response)

    challenge_req = nuki_messages.Request('0004')
    challenge_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=challenge_req, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    challenge_req_encrypted_command = challenge_req_encrypted.generate()

    print("Requesting CHALLENGE: %s" % challenge_req_encrypted.generate("HEX"))

    self._char_write_response = ""

    self.device.char_write_handle(key_turner_usd_io_handle,challenge_req_encrypted_command,True,5)
    print("Nuki CHALLENGE Request sent: %s" % challenge_req.show())

    command_parsed = self.parser.decrypt(self._char_write_response,self.config.get(self.mac_address, 'publicKeyNuki'),self.config.get(self.mac_address, 'privateKeyHex'))[8:]

    if self.parser.isNukiCommand(command_parsed) == False:
      sys.exit("Error while requesting Nuki CHALLENGE: %s" % command_parsed)

    command_parsed = self.parser.parse(command_parsed)

    if command_parsed.command != '0004':
      sys.exit("Nuki returned unexpected response (expecting Nuki CHALLENGE): %s" % command_parsed.show())

    print("Challenge received: %s" % command_parsed.nonce)

    log_entries_req = nuki_messages.LogEntriesRequest()
    log_entries_req.createPayload(count, command_parsed.nonce, self.byte_swapper.swap(pin_hex))
    log_entries_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=log_entries_req, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    log_entries_req_encrypted_command = log_entries_req_encrypted.generate()

    self._char_write_response = ""

    self.device.char_write_handle(key_turner_usd_io_handle,log_entries_req_encrypted_command,True,6)
    print("Nuki Log Entries Request sent: %s" % log_entries_req.show())

    messages = self.parser.splitEncryptedMessages(self._char_write_response)
    print("Received %d messages" % len(messages))

    log_messages = []
    for message in messages:
      print("Decrypting message %s" % message)
      try:
        command_parsed = self.parser.decrypt(message,self.config.get(self.mac_address, 'publicKeyNuki'),self.config.get(self.mac_address, 'privateKeyHex'))[8:]
        if self.parser.isNukiCommand(command_parsed) == False:
          sys.exit("Error while requesting Nuki Log Entries: %s" % command_parsed)
        command_parsed = self.parser.parse(command_parsed)
        if command_parsed.command != '0024' and command_parsed.command != '0026' and command_parsed.command != '000E':
          sys.exit("Nuki returned unexpected response (expecting Nuki LOG ENTRY): %s" % command_parsed.show())
        print("%s" % command_parsed.show())
        if command_parsed.command == '0024':
          log_messages.append(command_parsed)
      except:
        print("Unable to decrypt message")
    return log_messages
    