from .crc import CrcCalculator
from .byteswap import ByteSwapper
import array
import nacl.utils
import nacl.secret
from nacl.public import PrivateKey, Box
from nacl.bindings.crypto_box import crypto_box_beforenm
import hmac
import hashlib
import binascii
from .utils import *
from .errors import *


class EncryptedCommand(object):
  def __init__(self, authID='', nukiCommand=None, nonce=None, publicKey='', privateKey=''):
    self.byteSwapper = ByteSwapper()
    self.crcCalculator = CrcCalculator()
    self.authID = authID
    self.command = nukiCommand
    self.nonce = nonce
    if nonce is None:
      self.nonce = binascii.hexlify(nacl.utils.random(24))
    self.publicKey = publicKey
    self.privateKey = privateKey

  def generate(self, format='BYTE_ARRAY'):
    unencrypted = self.authID + self.command.generate(format='HEX')[:-4]
    crc = self.byteSwapper.swap(self.crcCalculator.crc_ccitt(unencrypted))
    unencrypted = unencrypted + crc

    sharedKey = binascii.hexlify(crypto_box_beforenm(binascii.unhexlify(self.publicKey), binascii.unhexlify(self.privateKey)))
    box = nacl.secret.SecretBox(binascii.unhexlify(sharedKey))

    encrypted = binascii.hexlify(box.encrypt(binascii.unhexlify(unencrypted), binascii.unhexlify(self.nonce)))[48:]
    length = self.byteSwapper.swap("%04X" % (len(encrypted)/2))

    msg = to_str(self.nonce) + to_str(self.authID) + to_str(length) + to_str(encrypted)
    if format == 'BYTE_ARRAY':
      return array.array('B', binascii.unhexlify(msg))
    else:
      return msg


class Command(object):
  def __init__(self, payload=""):
    self.crcCalculator = CrcCalculator()
    self.byteSwapper = ByteSwapper()
    self.parser = CommandParser()
    self.command = ''
    self.payload = payload

  def generate(self, format='BYTE_ARRAY'):
    msg = self.byteSwapper.swap(self.command) + to_str(self.payload)
    crc = self.byteSwapper.swap(self.crcCalculator.crc_ccitt(msg))
    msg = msg + crc
    if format == 'BYTE_ARRAY':
      return array.array('B', binascii.unhexlify(msg))
    else:
      return msg

  def isError(self):
    return self.command == '0012'


class Request(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '0001'
    self.payload = self.byteSwapper.swap(payload)

  def show(self):
    payloadParsed = self.parser.getNukiCommandText(self.byteSwapper.swap(self.payload))
    return "Request\n\tPayload: %s" % payloadParsed


class Error(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '0012'
    self.errorCode = '';
    self.commandIdentifier = '';
    if payload != "N/A":
      self.errorCode = payload[:2]
      self.commandIdentifier = self.byteSwapper.swap(payload[2:6])

  def show(self):
    payloadParsed = self.parser.getNukiCommandText(self.byteSwapper.swap(self.payload))
    return "Error\n\tError Code: %s\n\tCommand Identifier: %s" % (self.errorCode,self.commandIdentifier)


class PublicKey(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '0003'
    self.publicKey = '';
    if payload != "N/A":
      self.publicKey = payload

  def show(self):
    return "PublicKey\n\tKey: %s" % (self.publicKey)


class Challenge(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '0004'
    self.nonce = '';
    if payload != "N/A":
      self.nonce = payload

  def show(self):
    return "Challenge\n\tNonce: %s" % (self.nonce)


class AuthAuthenticator(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '0005'
    self.authenticator = ''
    if payload != "N/A":
      self.authenticator = payload

  def createPayload(self, nonceNuki, privateKeyAuth, publicKeyAuth, publicKeyNuki):
    sharedKey = binascii.hexlify(crypto_box_beforenm(bytes(bytearray.fromhex(publicKeyNuki)),bytes(bytearray.fromhex(privateKeyAuth.decode('utf-8'))))).decode('utf-8')

    valueR = to_str(publicKeyAuth) + to_str(publicKeyNuki) + to_str(nonceNuki)
    self.authenticator = hmac.new(bytearray.fromhex(sharedKey), msg=bytearray.fromhex(valueR), digestmod=hashlib.sha256).hexdigest()
    self.payload = self.authenticator

  def show(self):
    return "AuthAuthenticator\n\tAuthenticator: %s" % (self.authenticator)


class AuthData(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '0006'
    self.authenticator = ''
    self.idType = '01'
    self.appID = ''
    self.name = ''
    self.nonce = ''
    if payload != "N/A":
      self.authenticator = payload[:64]
      self.idType = payload[64:66]
      self.appID = payload[66:74]
      self.name = payload[74:138]
      self.nonce = payload[138:]

  def createPayload(self, publicKeyNuki, privateKeyAuth, publicKeyAuth, nonceNuki, appID, idType, name):
    self.appID = ("%x" % appID).rjust(8,'0')
    self.idType = idType
    self.name = binascii.hexlify(name.encode()).ljust(64, b'0')
    self.nonce = binascii.hexlify(nacl.utils.random(32))

    sharedKey = binascii.hexlify(crypto_box_beforenm(bytes(bytearray.fromhex(to_str(publicKeyNuki))),bytes(bytearray.fromhex(to_str(privateKeyAuth)))))
    valueR = to_str(self.idType) + to_str(self.appID) + to_str(self.name) + to_str(self.nonce) + to_str(nonceNuki)
    self.authenticator = hmac.new(bytearray.fromhex(to_str(sharedKey)), msg=bytearray.fromhex(valueR), digestmod=hashlib.sha256).hexdigest()
    self.payload = to_str(self.authenticator) + to_str(self.idType) + to_str(self.appID) + to_str(self.name) + to_str(self.nonce)

  def show(self):
    return "AuthData\n\tAuthenticator: %s\n\tID Type: %s\n\tAuthenticator ID: %s\n\tName: %s\n\tNonce: %s" % (self.authenticator, self.idType, self.appID, binascii.unhexlify(self.name), self.nonce)


class AuthID(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '0007'
    self.authenticator = ''
    self.authID = ''
    self.uuid = ''
    self.nonce = ''
    if payload != "N/A":
      self.authenticator = payload[:64]
      self.authID = payload[64:72]
      self.uuid = payload[72:104]
      self.nonce = payload[104:]

  def show(self):
    return "AuthID\n\tAuthenticator: %s\n\tAuthorization ID: %s\n\tUUID: %s\n\tNonce: %s" % (self.authenticator, self.authID, self.uuid, self.nonce)


class AuthIDConfirm(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '001E'
    self.authID = ''
    if payload != "N/A":
      self.authenticator = payload[:64]
      self.authID = payload[64:]

  def show(self):
    return "AuthIDConfirm\n\tAuthenticator: %s\n\tAuthorization ID: %s" % (self.authenticator, self.authID)

  def createPayload(self, publicKeyNuki, privateKeyAuth, publicKeyAuth, nonceNuki, authID):
    self.authID = ("%x" % authID).rjust(8,'0')

    sharedKey = binascii.hexlify(crypto_box_beforenm(bytes(bytearray.fromhex(to_str(publicKeyNuki))),bytes(bytearray.fromhex(to_str(privateKeyAuth)))))
    valueR = to_str(self.authID) + to_str(nonceNuki)
    self.authenticator = hmac.new(bytearray.fromhex(to_str(sharedKey)), msg=bytearray.fromhex(valueR), digestmod=hashlib.sha256).hexdigest()
    self.payload = self.authenticator + self.authID


class Status(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '000E'
    self.status = ''
    if payload != "N/A":
      self.status = payload

  def show(self):
    return "Status\n\tStatus: %s" % (self.status)


class States(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '000C'
    self.nukiState = ''
    self.lockState = ''
    self.trigger = ''
    self.currentTime = ''
    self.timeOffset = ''
    self.criticalBattery = ''
    if payload != "N/A":
      payload = payload.upper()
      self.nukiState = payload[:2]
      if self.nukiState == '00':
        self.nukiState = 'Uninitialized'
      elif self.nukiState == '01':
        self.nukiState = 'Pairing Mode'
      elif self.nukiState == '02':
        self.nukiState = 'Door Mode'
      self.lockState = payload[2:4]
      if self.lockState == '00':
        self.lockState = 'Uncalibrated'
      elif self.lockState == '01':
        self.lockState = 'Locked'
      elif self.lockState == '02':
        self.lockState = 'Unlocking'
      elif self.lockState == '03':
        self.lockState = 'Unlocked'
      elif self.lockState == '04':
        self.lockState = 'Locking'
      elif self.lockState == '05':
        self.lockState = 'Unlatched'
      elif self.lockState == '06':
        self.lockState = 'Unlocked (lockNGo)'
      elif self.lockState == '07':
        self.lockState = 'Unlatching'
      elif self.lockState == 'FE':
        self.lockState = 'Motor Blocked'
      elif self.lockState == 'FF':
        self.lockState = 'Undefined'
      self.trigger = payload[4:6]
      if self.trigger == '00':
        self.trigger = 'Bluetooth'
      elif self.trigger == '01':
        self.trigger = 'Manual'
      elif self.trigger == '02':
        self.trigger = 'Button'
      year = int(self.byteSwapper.swap(payload[6:10]),16)
      month = int(payload[10:12],16)
      day = int(payload[12:14],16)
      hour = int(payload[14:16],16)
      minute = int(payload[16:18],16)
      second = int(payload[18:20],16)
      self.currentTime = "%02d-%02d-%d %02d:%02d:%02d" % (day,month,year,hour,minute,second)
      self.timeOffset = int(self.byteSwapper.swap(payload[20:24]),16)
      self.criticalBattery = payload[24:26]
      if self.criticalBattery == '00':
        self.criticalBattery = 'OK'
      elif self.criticalBattery == '01':
        self.criticalBattery = 'Critical'

  def show(self):
    return "States\n\tNuki Status: %s\n\tLock Status: %s\n\tTrigger: %s\n\tCurrent Time: %s\n\tTime Offset: %s\n\tCritical Battery: %s" % (self.nukiState,self.lockState,self.trigger,self.currentTime,self.timeOffset,self.criticalBattery)


class LockAction(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '000D'
    self.lockAction = ''
    self.appID = ''
    self.flags = '00'
    self.nonce = ''
    if payload != "N/A":
      self.authenticator = payload[:64]
      self.authID = payload[64:]

  def show(self):
    return "LockAction\n\tLock Action: %s\n\tAPP ID: %s\n\tFlags: %s\n\tNonce: %s" % (self.lockAction,self.appID,self.flags,self.nonce)

  def createPayload(self, appID, lockAction, nonce):
    self.appID = ("%x" % appID).rjust(8,'0')
    self.nonce = nonce
    if lockAction == 'UNLOCK':
      self.lockAction = '01'
    elif lockAction == 'LOCK':
      self.lockAction = '02'
    elif lockAction == 'UNLATCH':
      self.lockAction = '03'
    elif lockAction == 'LOCKNGO':
      self.lockAction = '04'
    elif lockAction == 'LOCKNGO_UNLATCH':
      self.lockAction = '05'
    elif lockAction == 'FOB_ACTION_1':
      self.lockAction = '81'
    elif lockAction == 'FOB_ACTION_2':
      self.lockAction = '82'
    elif lockAction == 'FOB_ACTION_3':
      self.lockAction = '83'
    else:
      raise LockCommandActionUnsupported(lockAction)
    self.payload = to_str(self.lockAction) + to_str(self.appID) + to_str(self.flags) + to_str(self.nonce)


class LogEntriesRequest(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '0023'
    self.mostRecent = '00'
    self.startIndex = '0000'
    self.count = ''
    self.nonce = ''
    self.pin = ''
    if payload != "N/A":
      self.mostRecent = payload[:2]
      self.startIndex = payload[2:6]
      self.count = payload[6:10]
      self.nonce = payload[10:74]
      self.pin = payload[74:]

  def show(self):
    return "Nuki_LOCK_ENTRIES_REQUEST\n\tMost Recent: %s\n\tStart Index: %s\n\tCount: %s\n\tNonce: %s\n\tPIN: %s" % (self.mostRecent,self.startIndex,self.count,self.nonce,self.pin)

  def createPayload(self, count, nonce, pin):
    self.mostRecent = '01'
    self.startIndex = self.byteSwapper.swap("%04x" % 0)
    self.count = self.byteSwapper.swap("%04x" % count)
    self.nonce = nonce
    self.pin = pin
    self.payload = to_str(self.mostRecent) + to_str(self.startIndex) + to_str(self.count) + to_str(self.nonce) + to_str(self.pin)


class CalibrationRequest(Command):
  def __init__(self, payload='N/A'):
    super(self.__class__, self).__init__(payload)
    self.command = '001A'
    self.nonce = None
    self.pin = None
    self.payload = payload
    if self.payload != "N/A":
      self.nonce = payload[:64]
      self.pin = payload[64:]

  def show(self):
    return 'Nuki Calibration Request sent'

  def create_payload(self, nonce, pin):
    self.nonce = nonce
    self.pin = pin
    self.payload = to_str(self.nonce) + to_str(self.pin)
    return self.payload


class LogEntryCount(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '0026'
    self.logEnabled = ''
    self.logCount = ''
    if payload != "N/A":
      payload = payload.upper()
      self.logEnabled = payload[:2]
      if self.logEnabled == '00':
        self.logEnabled = 'DISABLED'
      elif self.logEnabled == '01':
        self.logEnabled = 'ENABLED'
      self.logCount = self.byteSwapper.swap(payload[2:6])

  def show(self):
    return "LogEntryCount\n\tLOG: %s\n\tCount: %d" % (self.logEnabled, int(self.logCount, 16))


class LogEntry(Command):
  def __init__(self, payload="N/A"):
    super(self.__class__, self).__init__(payload)
    self.command = '0024'
    self.index = ''
    self.timestamp = ''
    self.name = ''
    self.type = ''
    self.data = ''
    if payload != "N/A":
      payload = payload.upper()
      self.index = int(self.byteSwapper.swap(payload[:4]),16)
      year = int(self.byteSwapper.swap(payload[4:8]),16)
      month = int(payload[8:10],16)
      day = int(payload[10:12],16)
      hour = int(payload[12:14],16)
      minute = int(payload[14:16],16)
      second = int(payload[16:18],16)
      self.timestamp = "%02d-%02d-%d %02d:%02d:%02d" % (day,month,year,hour,minute,second)
      self.name = payload[18:82]
      self.type = payload[82:84]
      if self.type == '01':
        self.type = 'LOG'
        self.data = payload[84:86]
        if self.data == '00':
          self.data = 'DISABLED'
        elif self.data == '01':
          self.data = 'ENABLED'
      elif self.type == '02':
        self.type = 'LOCK'
        lockAction = payload[84:86]
        if lockAction == '01':
          self.data = 'UNLOCK'
        elif lockAction == '02':
          self.data = 'LOCK'
        elif lockAction == '03':
          self.data = 'UNLATCH'
        elif lockAction == '04':
          self.data = 'LOCKNGO'
        elif lockAction == '05':
          self.data = 'LOCKNGO_UNLATCH'
        elif lockAction == '81':
          self.data = 'FOB_ACTION_1'
        elif lockAction == '82':
          self.data = 'FOB_ACTION_2'
        elif lockAction == '83':
          self.data = 'FOB_ACTION_3'
        trigger = payload[86:88]
        if trigger == '00':
          self.data = "%s - via Bluetooth" % self.data
        elif trigger == '01':
          self.data = "%s - manual" % self.data
          self.name = binascii.hexlify(b"N/A")
        elif trigger == '02':
          self.data = "%s - via button" % self.data
          self.name = binascii.hexlify(b"N/A")

  def show(self):
    return "LogEntry\n\tIndex: %d\n\tTimestamp: %s\n\tName: %s\n\tType: %s\n\tData: %s" % (self.index, self.timestamp, binascii.unhexlify(self.name), self.type, self.data)


class CommandParser:
  def __init__(self):
    self.byteSwapper = ByteSwapper()
    self.commandList = ['0001','0003','0004','0005','0006','0007','000C','001E','000E','0023','0024','0026','001A','0012']

  def isNukiCommand(self, commandString):
    command = self.byteSwapper.swap(commandString[:4])
    return command.upper() in self.commandList

  def getNukiCommandText(self, command):
    return {
      '0001': 'Request',
      '0003': 'PublicKey',
      '0004': 'Challenge',
      '0005': 'AuthAuthenticator',
      '0006': 'AuthData',
      '0007': 'AuthID',
      '000C': 'States',
      '001E': 'AuthIDConfirm',
      '000E': 'Status',
      '0023': 'Nuki_LOCK_ENTRIES_REQUEST',
      '0024': 'LogEntry',
      '0026': 'LogEntryCount',
      '001A': 'NukiRequestCalibration',
      '0012': 'Error',
    }.get(command.upper(), 'UNKNOWN')    # UNKNOWN is default if command not found

  def parse(self, commandString):
    if self.isNukiCommand(commandString):
      command = self.byteSwapper.swap(commandString[:4]).upper()
      payload = commandString[4:-4]
      crc = self.byteSwapper.swap(commandString[-4:])
      # print("command = %s, payload = %s, crc = %s" % (command,payload,crc))
      if command == '0001':
        return Request(payload)
      elif command == '0003':
        return PublicKey(payload)
      elif command == '0004':
        return Challenge(payload)
      elif command == '0005':
        return AuthAuthenticator(payload)
      elif command == '0006':
        return AuthData(payload)
      elif command == '0007':
        return AuthID(payload)
      elif command == '000C':
        return States(payload)
      elif command == '001E':
        return AuthIDConfirm(payload)
      elif command == '000E':
        return Status(payload)
      elif command == '0023':
        return LogEntriesRequest(payload)
      elif command == '0024':
        return LogEntry(payload)
      elif command == '0026':
        return LogEntryCount(payload)
      elif command == '001A':
        return CalibrationRequest(payload)
      elif command == '0012':
        return Error(payload)
    else:
      return "%s does not seem to be a valid Nuki command" % commandString

  def splitEncryptedMessages(self, msg):
    msgList = []
    offset = 0
    while offset < len(msg):
      nonce = msg[offset:offset+48]
      authID = msg[offset+48:offset+56]
      length = int(self.byteSwapper.swap(msg[offset+56:offset+60]), 16)
      singleMsg = msg[offset:offset+60+(length*2)]
      msgList.append(singleMsg)
      offset = offset+60+(length*2)
    return msgList

  def decrypt(self, msg, publicKey, privateKey):
    # print("msg: %s" % msg)
    nonce = msg[:48]
    # print("nonce: %s" % nonce)
    authID = msg[48:56]
    # print("authID: %s" % authID)
    length = int(self.byteSwapper.swap(msg[56:60]), 16)
    # print("length: %d" % length)
    encrypted = nonce + msg[60:60+(length*2)]
    # print("encrypted: %s" % encrypted)
    sharedKey = binascii.hexlify(crypto_box_beforenm(binascii.unhexlify(publicKey), binascii.unhexlify(privateKey)))
    box = nacl.secret.SecretBox(binascii.unhexlify(sharedKey))
    decrypted = binascii.hexlify(box.decrypt(binascii.unhexlify(encrypted)))
    print("decrypted: %s" % decrypted)
    return decrypted


if __name__ == "__main__":
  parser = CommandParser()
  commandString = "0600CF1B9E7801E3196E6594E76D57908EE500AAD5C33F4B6E0BBEA0DDEF82967BFC00000000004D6172632028546573742900000000000000000000000000000000000000000052AFE0A664B4E9B56DC6BD4CB718A6C9FED6BE17A7411072AA0D31537814057769F2"
  commandParsed = parser.parse(commandString)
  if parser.isNukiCommand(commandString):
    commandShow = commandParsed.show()
    print(commandShow)
  else:
    print(commandParsed)
  print("Done")
