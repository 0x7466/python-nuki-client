class BaseError(Exception):
  """
  Base class for exceptions in this module.
  """
  pass


class BLEDeviceAccessError(BaseError):
  """
  Raised if BLE adapter not accessible.
  """
  def __init__(self, value):
    self.value = value

  def __str__(self):
    return repr(self.value)


class CommandParseError(BaseError):
  """
  Raised if there is a problem
  with a Nuki command.
  """
  def __init__(self, method, request, value):
    self.method = method
    self.request = request
    self.value = value

  def __str__(self):
    return repr('In {} - request of {} - {}'.format(self.method, self.request, self.value))


class CommandMismatchError(BaseError):
  """
  Raised if there is a mismatch
  in the requested and responded command.
  """
  def __init__(self, expected, actual):
    self.expected = expected
    self.actual = actual

  def __str__(self):
    return repr('Wrong command returned - Expected: {} | Actual: {}'.format(self.expected, self.actual))


class LockCommandActionUnsupportedError(BaseError):
  """
  Raised if lock action to execute
  is not supported by the KT.
  """
  def __init__(self, action):
    self.action = action

  def __str__(self):
    return repr('Command not supported. ({})'.format(self.action))
