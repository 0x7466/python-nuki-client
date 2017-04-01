import nacl.utils
import pygatt.backends
import array
import configparser
import bluetooth._bluetooth as bluez
import logging

from nacl.public import PrivateKey, Box
from . import nuki_messages, blescan
from .byteswap import ByteSwapper
from .crc import CrcCalculator
from .utils import *
from .errors import *


class Nuki():
  def __init__(self, mac_address, config_path='./nuki.cfg'):
    """
    Creates a BLE connection with your Nuki KT.
    :param mac_address: The MAC address of the KT.
    """
    self.mac_address = mac_address
    self.config_path = config_path

    self._char_write_response = ''

    self.parser = nuki_messages.CommandParser()
    self.crc_calculator = CrcCalculator()
    self.byte_swapper = ByteSwapper()

    self.config = configparser.ConfigParser()
    self.config.read(self.config_path)

    self.config_data = None

    if self.mac_address in self.config.sections():
      self.config_data = self.config[self.mac_address]

    self.adapter = None
    self.device = None

    self.logger = logger = logging.getLogger('Nuki Client')



  def _handles_ble_requests(func):
    def wrapper(self, *args, **kwargs):
      self._make_ble_connection()
      try:
        func(self, *args, **kwargs)
      except Exception as err:
        self._close_ble_connection()
        raise err
      self._close_ble_connection()
    return wrapper


  def _make_ble_connection(self):
    """
    Establishes the BLE connection to the KT.
    Private method.
    """
    self.adapter = pygatt.backends.GATTToolBackend()
    nuki_ble_connection_ready = False

    while not nuki_ble_connection_ready:
      self.logger.debug("Starting BLE adapter...")
      self.adapter.start()
      self.logger.debug("Init Nuki BLE connection...")
      try :
        self.device = self.adapter.connect(self.mac_address)
        nuki_ble_connection_ready = True
      except:
        self.logger.warning("Unable to connect, retry...")

    self.logger.debug("Nuki BLE connection established")


  def _close_ble_connection(self):
    """
    Closes the connection and thread.
    """
    if self.adapter is not None:
      self.logger.debug('Close BLE Connection...')
      self.adapter.stop()


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
    self.device.char_write_handle(handle, request_command, True, 10)
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

    command_encrypted = nuki_messages.EncryptedCommand(authID=self.config_data['authorizationID'], nukiCommand=command, publicKey=self.config_data['publicKeyNuki'], privateKey=self.config_data['privateKeyHex'])
    request_command = command_encrypted.generate()

    self.logger.debug('Request Nuki using command: {}'.format(command.show()))
    self.device.char_write_handle(handle, request_command, True, 10)
    self.logger.debug('Nuki requested')

    command_parsed = self.parser.decrypt(self._char_write_response, self.config_data['publicKeyNuki'], self.config_data['privateKeyHex'])[8:]

    ## Validate
    if not self.parser.isNukiCommand(command_parsed):
      raise CommandParseError('req', command_id, command_parsed)

    command_parsed = self.parser.parse(command_parsed)

    if command_parsed.command != command_id:
      raise CommandMismatchError(command_id, command_parsed.command)

    return command_parsed


  @_handles_ble_requests
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
    self.config[self.mac_address] = {}

    
    handle = self._subscribe('a92ee101-5501-11e4-916c-0800200c9a66')


    # Requests the PK of the KT.
    command_id = '0003'
    request = nuki_messages.Request(command_id)
    command_parsed = self._make_request(request, handle, command_id=command_id)

    public_key_nuki = command_parsed.publicKey
    self.logger.debug('Public key received: {}'.format(public_key_nuki))

    

    self.config[self.mac_address] = {
      'publicKeyNuki': to_str(public_key_nuki),
      'publicKeyHex': to_str(public_key_hex),
      'privateKeyHex': to_str(private_key_hex),
      'ID': to_str(id),
      'IDType': to_str(id_type),
      'name': to_str(name)
    }



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
    self.config[self.mac_address]['authorizationID'] = to_str(authorization_id)


    # Sends the auth ID confirmation request.
    authid = int(command_parsed.authID, 16)
    request = nuki_messages.AuthIDConfirm()
    request.createPayload(public_key_nuki, private_key_hex, public_key_hex, nonce_nuki, authid)

    command_parsed = self._make_request(request, handle, '000E')

    with open(self.config_path, 'wt') as configfile:
      self.config.write(configfile)

    self.logger.info('STATUS received: {}'.format(command_parsed.status))

    return command_parsed.status
  


  @_handles_ble_requests
  def read_lock_state(self):
    """
    Reads the current lock state from the KT.
    """
    handle = self._subscribe('a92ee202-5501-11e4-916c-0800200c9a66')
    request = nuki_messages.Request(payload='000C')
    command_parsed = self._make_encrypted_request(request, handle, '000C')

    self.logger.info(command_parsed.show())
    return command_parsed
    


  @_handles_ble_requests
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
    handle = self._subscribe('a92ee202-5501-11e4-916c-0800200c9a66')

    # Request challenge
    request = nuki_messages.Request('0004')
    command_parsed = self._make_encrypted_request(request, handle, '0004')
    self.logger.debug('Challenge received: {}'.format(command_parsed.nonce))

    # Send lock action
    request = nuki_messages.LockAction()
    request.createPayload(int(self.config_data['ID']), lock_action, command_parsed.nonce)
    command_parsed = self._make_encrypted_request(request, handle, '000E')

    self.logger.info(command_parsed.show())
    return command_parsed



  @_handles_ble_requests
  def request_calibration(self, pin=0000):
    """
    Requests calibration of the KT.

    :param pin: The 2-byte PIN code set at the KT. (Default: 0000)
    """
    pin_hex = '%04x' % pin

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


  @_handles_ble_requests
  def get_log_entries_count(self, pin=0000):
    """
    Fetches the count of the log entries at the KT.

    :param pin: The 2-byte PIN code set at the KT. (Default: 0000)
    """
    pin_hex = '%04x' % pin

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
  


  @_handles_ble_requests
  def get_log_entries(self, count, pin=0000):
    """
    Fetches log entries form the KT.
    Starts with the most recent one.

    :param count: The number of entries which should be fetched.
    :param pin: The 2-byte PIN code set at the KT. (Default: 0000)
    """
    pin_hex = '%04x' % pin

    handle = self._subscribe('a92ee202-5501-11e4-916c-0800200c9a66')
    

    # Request challenge
    request = nuki_messages.Request('0004')
    command_parsed = self._make_encrypted_request(request, handle, '0004')
    self.logger.debug('Challenge received: {}'.format(command_parsed.nonce))


    request = nuki_messages.LogEntriesRequest()
    request.createPayload(count, command_parsed.nonce, self.byte_swapper.swap(pin_hex))
    log_entries_req_encrypted = nuki_messages.EncryptedCommand(authID=self.config_data['authorizationID'], nukiCommand=request, publicKey=self.config_data['publicKeyNuki'], privateKey=self.config_data['privateKeyHex'])
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
        command_parsed = self.parser.decrypt(message, self.config_data['publicKeyNuki'], self.config_data['privateKeyHex'])[8:]
        
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
    