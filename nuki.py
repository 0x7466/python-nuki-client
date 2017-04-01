import nacl.utils
import pygatt.backends
import array
import nuki_messages
import configparser
import blescan
import bluetooth._bluetooth as bluez
import logging

from nacl.public import PrivateKey, Box
from byteswap import ByteSwapper
from crc import CrcCalculator
from utils import *
from errors import *


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
    self.logger = logger = logging.getLogger(__name__)


  def _make_ble_connection(self):
    """
    Establishes the BLE connection to the KT.
    Private method.
    """
    adapter = pygatt.backends.GATTToolBackend()
    nuki_ble_connection_unready = True

    while nuki_ble_connection_unready:
      self.logger.debug("Starting BLE adapter...")
      adapter.start()
      self.logger.debug("Init Nuki BLE connection...")
      try :
        self.device = adapter.connect(self.mac_address)
        nuki_ble_connection_unready = False
      except:
        self.logger.warning("Unable to connect, retry...")

    self.logger.debug("Nuki BLE connection established")
  

  def is_new_nuki_state_available(self):
    """
    Checks if a new KT state is available.
    Only works if script is running as root.
    """
    if self.device is not None:
      self.device.disconnect()
      self.device = None
      
    dev_id = 0
    try:
      sock = bluez.hci_open_dev(dev_id)
    except:
      raise BLEDeviceAccessError('Error accessing BLE device.')

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
  

  def _subscribe(self, uuid):
    handle = self.device.get_handle(uuid)
    self.logger.debug("UUID handle created: %04x" % handle)

    self.device.subscribe(uuid, self._handle_char_write_response)

    return handle


  def _make_request(self, command, handle, command_id=None):
    if command_id is None:
      command_id = command.command

    self._char_write_response = ''

    request_command = command.generate()

    self.logger.debug('Request Nuki using command: {}'.format(command.show()))
    self.device.char_write_handle(handle, request_command, True, 5)
    self.logger.debug('Nuki requested')

    command_parsed = self.parser.parse(self._char_write_response)

    ## Validate
    if not self.parser.isNukiCommand(self._char_write_response):
      raise CommandParseError('req', command_id, command_parsed)

    if command_parsed.command != command_id:
      raise CommandMismatchError(command_id, command_parsed.command)

    return command_parsed

  
  def _make_encrypted_request(self, command, handle, command_id=None):
    if command_id is None:
      command_id = command.command

    self._char_write_response = ''

    command_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=command, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    request_command = command_encrypted.generate()

    self.logger.debug('Request Nuki using command: {}'.format(command.show()))
    self.device.char_write_handle(handle, request_command, True, 5)
    self.logger.debug('Nuki requested')

    command_parsed = self.parser.decrypt(self._char_write_response, self.config.get(self.mac_address, 'publicKeyNuki'), self.config.get(self.mac_address, 'privateKeyHex'))[8:]

    ## Validate
    if not self.parser.isNukiCommand(command_parsed):
      raise CommandParseError('req', command_id, command_parsed)

    command_parsed = self.parser.parse(command_parsed)

    if command_parsed.command != command_id:
      raise CommandMismatchError(command_id, command_parsed.command)

    return command_parsed


  def authenticate_user(self, public_key_hex, private_key_hex, id, id_type, name):
    """
    Authorizes a new user. The KT has to be in inclusion mode for this process.
    Press and hold the button on the KT for 5 seconds until the light is on.

    The process looks as following:
     - Requests the PK of the KT.
     - Sends the PK and receives the challenge.
     - Sends an auth authenticator request and receives a challenge again.
     - Sends an auth data request and receives the auth ID.
     - Sends the auth ID confirmation request.

    :param public_key_hex: The public key which should be authorized.
    :param private_key_hex: The private key which belongs to the public key.
    :param id: A unique identifier to identify the user.
    :param id_type: The type of the user. ('00' => 'app', '01' => 'bridge', '02' => 'fob')
    :param name: The display name for this user. (Appears in the logs)
    """
    self._make_ble_connection()

    self.config.remove_section(self.mac_address)
    self.config.add_section(self.mac_address)

    handle = self._subscribe('a92ee101-5501-11e4-916c-0800200c9a66')



    # Requests the PK of the KT.
    command_id = '0003'
    request = nuki_messages.Request(command_id)
    command_parsed = self._make_request(request, handle, command_id=command_id)

    public_key_nuki = command_parsed.publicKey
    self.logger.debug('Public key received: {}'.format(public_key_nuki))

    # Stores the information in the config.
    self.config.set(self.mac_address, 'publicKeyNuki', to_str(public_key_nuki))
    self.config.set(self.mac_address, 'publicKeyHex', to_str(public_key_hex))
    self.config.set(self.mac_address, 'privateKeyHex', to_str(private_key_hex))
    self.config.set(self.mac_address, 'ID', to_str(id))
    self.config.set(self.mac_address, 'IDType', to_str(id_type))
    self.config.set(self.mac_address, 'name', to_str(name))



    # Sends the PK and receives the challenge.
    request = nuki_messages.PublicKey(public_key_hex)
    command_parsed = self._make_request(request, handle, command_id='0004')

    nonce_nuki = command_parsed.nonce
    self.logger.debug('Challenge received: {}'.format(nonce_nuki))
    


    # Sends an auth authenticator request and receives a challenge again.
    request = nuki_messages.AuthAuthenticator()
    request.createPayload(nonce_nuki, private_key_hex, public_key_hex, public_key_nuki)

    command_parsed = self._make_request(request, handle, '0004')

    nonce_nuki = command_parsed.nonce
    self.logger.debug('Challenge received: {}'.format(nonce_nuki))


    # Sends an auth data request and receives the auth ID.
    request = nuki_messages.AuthData()
    request.createPayload(public_key_nuki, private_key_hex, public_key_hex, nonce_nuki, id, id_type, name)

    command_parsed = self._make_request(request, handle, '0007')

    self.logger.debug('Authorization ID received: {}'.format(command_parsed.show()))
    nonce_nuki = command_parsed.nonce

    authorization_id = command_parsed.authID
    self.config.set(self.mac_address, 'authorizationID', to_str(authorization_id))


    # Sends the auth ID confirmation request.
    authid = int(command_parsed.authID, 16)
    request = nuki_messages.AuthIDConfirm()
    request.createPayload(public_key_nuki, private_key_hex, public_key_hex, nonce_nuki, authid)

    command_parsed = self._make_request(request, handle, '000E')

    with open('./nuki.cfg', 'at') as configfile:
      self.config.write(configfile)

    self.logger.info('STATUS received: {}'.format(command_parsed.status))
    return command_parsed.status
  


  def read_lock_state(self):
    """
    Reads the current lock state from the KT.
    """
    self._make_ble_connection()

    handle = self._subscribe('a92ee202-5501-11e4-916c-0800200c9a66')
    request = nuki_messages.Request(payload='000C')
    command_parsed = self._make_encrypted_request(request, handle, '000C')

    self.logger.info(command_parsed.show())
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
    handle = self._subscribe('a92ee202-5501-11e4-916c-0800200c9a66')

    # Request challenge
    request = nuki_messages.Request('0004')
    command_parsed = self._make_encrypted_request(request, handle, '0004')
    self.logger.debug('Challenge received: {}'.format(command_parsed.nonce))

    # Send lock action
    request = nuki_messages.LockAction()
    request.createPayload(self.config.getint(self.mac_address, 'ID'), lock_action, command_parsed.nonce)
    command_parsed = self._make_encrypted_request(request, handle, '000E')

    self.logger.info(command_parsed.show())
    return command_parsed


  def request_calibration(self, pin=0000):
    """
    Requests calibration of the KT.

    :param pin: The 2-byte PIN code set at the KT. (Default: 0000)
    """
    pin_hex = '%04x' % pin

    self._make_ble_connection()
    handle = self._subscribe('a92ee202-5501-11e4-916c-0800200c9a66')

    # Request challenge
    request = nuki_messages.Request('0004')
    command_parsed = self._make_encrypted_request(request, handle, '0004')
    self.logger.debug('Challenge received: {}'.format(command_parsed.nonce))


    # Send calibration request
    request = nuki_messages.CalibrationRequest()
    request.create_payload(command_parsed.nonce, self.byte_swapper.swap(pin_hex))
    command_parsed = self._make_encrypted_request(request, handle, '000E')

    self.logger.info(command_parsed.show())
    return command_parsed


  def get_log_entries_count(self, pin=0000):
    """
    Fetches the count of the log entries at the KT.

    :param pin: The 2-byte PIN code set at the KT. (Default: 0000)
    """
    pin_hex = '%04x' % pin

    self._make_ble_connection()
    handle = self._subscribe('a92ee202-5501-11e4-916c-0800200c9a66')


    # Request challenge
    request = nuki_messages.Request('0004')
    command_parsed = self._make_encrypted_request(request, handle, '0004')
    self.logger.debug('Challenge received: {}'.format(command_parsed.nonce))


    # Make log entry count request
    request = nuki_messages.LogEntriesRequest()
    request.createPayload(0, command_parsed.nonce, self.byte_swapper.swap(pin_hex))
    command_parsed = self._make_encrypted_request(request, handle, '0026')


    self.logger.info(command_parsed.show())
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
    handle = self._subscribe('a92ee202-5501-11e4-916c-0800200c9a66')
    

    # Request challenge
    request = nuki_messages.Request('0004')
    command_parsed = self._make_encrypted_request(request, handle, '0004')
    self.logger.debug('Challenge received: {}'.format(command_parsed.nonce))


    request = nuki_messages.LogEntriesRequest()
    request.createPayload(count, command_parsed.nonce, self.byte_swapper.swap(pin_hex))
    log_entries_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config.get(self.mac_address, 'authorizationID'), nukiCommand=request, publicKey=self.config.get(self.mac_address, 'publicKeyNuki'), privateKey=self.config.get(self.mac_address, 'privateKeyHex'))
    log_entries_req_encrypted_command = log_entries_req_encrypted.generate()

    self._char_write_response = ""

    self.device.char_write_handle(handle, log_entries_req_encrypted_command, True, 6)
    self.logger.debug('Nuki Log Entries Request sent: {}'.format(request.show()))

    messages = self.parser.splitEncryptedMessages(self._char_write_response)
    self.logger.debug('Received {} messages'.format(len(messages)))

    log_messages = []
    for message in messages:
      self.logger.debug('Decrypting message {}'.format(message))
      try:
        command_parsed = self.parser.decrypt(message,self.config.get(self.mac_address, 'publicKeyNuki'),self.config.get(self.mac_address, 'privateKeyHex'))[8:]
        
        if not self.parser.isNukiCommand(command_parsed):
          raise CommandParseError('get_log_entries', 'Log Entries', command_parsed)

        command_parsed = self.parser.parse(command_parsed)

        if command_parsed.command != '0024' and command_parsed.command != '0026' and command_parsed.command != '000E':
          raise CommandMismatchError('0024/0026/000E', command_parsed.command)

        self.logger.info(command_parsed.show())

        if command_parsed.command == '0024':
          log_messages.append(command_parsed)
      except:
        self.logger.error('Unable to decrypt message')

    return log_messages
    