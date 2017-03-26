def to_str(data):
  if isinstance(data, bytes):
    data = data.decode()
  elif isinstance(data, bytearray):
    data = data.decode('latin-1')
  elif isinstance(data, int):
    data = str(data)

  return data