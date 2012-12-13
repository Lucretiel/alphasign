import time
import re
from itertools import imap

from alphasign import constants
from alphasign import packet

import alphasign.string
import alphasign.text


class BaseInterface(object):
  """Base interface from which all other interfaces inherit.

  This class contains utility methods for fundamental sign features.
  """

  #TODO: perhaps raise a NotImplementedError here?
  def write(self, data):
    return False
  
  def read(self):
    return False
  
  def request(self, data):
    """Writes the packet to the interface, then listens for and returns
    a response
    
    :param data: packet to write
    :type data: :class:`alphasign.packet.Packet`
    :returns: string containing the data. False if there was an error with the read or write.
    """
    
    if self.write(data):
      return self.read()
    return False

  def clear_memory(self):
    """Clear the sign's memory.

    :rtype: None
    """
    pkt = packet.Packet("%s%s" % (constants.WRITE_SPECIAL, "$"))
    self.write(pkt)
    time.sleep(1)

  def beep(self, frequency=0, duration=0.1, repeat=0):
    """Make the sign beep.

    :param frequency: frequency integer (not in Hz), 0 - 254
    :param duration: beep duration, 0.1 - 1.5
    :param repeat: number of times to repeat, 0 - 15

    :rtype: None
    """
    if frequency < 0:
      frequency = 0
    elif frequency > 254:
      frequency = 254

    duration = int(duration / 0.1)
    if duration < 1:
      duration = 1
    elif duration > 15:
      duration = 15

    if repeat < 0:
      repeat = 0
    elif repeat > 15:
      repeat = 15

    pkt = packet.Packet("%s%s%02X%X%X" % (constants.WRITE_SPECIAL, "(2",
                                          frequency, duration, repeat))
    self.write(pkt)

  def soft_reset(self):
    """Perform a soft reset on the sign.

    This is non-destructive and does not clear the sign's memory.

    :rtype: None
    """
    pkt = packet.Packet("%s%s" % (constants.WRITE_SPECIAL, ","))
    self.write(pkt)

  def allocate(self, files):
    """Allocate a set of files on the device.

    :param files: list of file objects (:class:`alphasign.text.Text`,
                                        :class:`alphasign.string.String`, ...)

    :rtype: None
    """
    seq = ""
    for obj in files:
      size_hex = "%04X" % obj.size
      # format: FTPSIZEQQQQ

      if type(obj) == alphasign.string.String:
        file_type = "B"
        qqqq = "0000"  # unused for strings
        lock = constants.LOCKED
      else:  # if type(obj) == alphasign.text.Text:
        file_type = "A"
        qqqq = "FFFF"  # TODO(ms): start/end times
        lock = constants.UNLOCKED

      alloc_str = ("%s%s%s%s%s" %
                   (obj.label,  # file label to allocate
                   file_type,   # file type
                   lock,
                   size_hex,    # size in hex
                   qqqq))
      seq += alloc_str

    # allocate special TARGET TEXT files 1 through 5
    for i in range(5):
      alloc_str = ("%s%s%s%s%s" %
                   ("%d" % (i + 1),
                   "A",    # file type
                   constants.UNLOCKED,
                   "%04X" % 100,
                   "FEFE"))
      seq += alloc_str

    pkt = packet.Packet("%s%s%s" % (constants.WRITE_SPECIAL, "$", seq))
    self.write(pkt)

  def set_run_sequence(self, files, locked=False):
    """Set the run sequence on the device.

    This determines the order in which the files are displayed on the device, if
    at all. This is useful when handling multiple TEXT files.

    :param files: list of file objects (:class:`alphasign.text.Text`,
                                        :class:`alphasign.string.String`, ...)
    :param locked: allow sequence to be changed with IR keyboard

    :rtype: None
    """
    seq_str = ".T"
    seq_str += locked and "L" or "U"
    for obj in files:
      seq_str += obj.label
    pkt = packet.Packet("%s%s" % (constants.WRITE_SPECIAL, seq_str))
    self.write(pkt)
    
  def read_raw_memory_table(self):
    """Reads the current memory table as a raw string
    
    This function reads the raw memory configuration from the sign, extracts
    the data table portion, and returns it raw. 
    
    :returns: raw memory layout. False if there was an error in the process.
    """
    memory = self.request(packet.Packet('F$'))
    if memory == False or memory == '':
      return False
    
    #TODO: checksum verification
    
    #This pattern extracts the table and checksum from the packet
    pattern = "\x00+\x01000\x02E\$(?P<table>(?:[\x20-\x7F][ABD][UL][0-9A-Fa-f]{4}[0-9A-Fa-f]{4})*)\x03(?P<checksum>[0-9A-Fa-f]{4})\x04"
    match = re.match(pattern, memory)
    if match is not None:
      return match.group('table')
    else:
      return False
  
  def read_memory_table(self, label=None):
    """Reads and parses the sign's current memory table.
    
    This function reads and parses the sign's current memory table into a list
    of dicts, where each dict corrosponds to an entry in the table. If the
    label parameter is given, search the table instead, and return the
    corrosponding entry (or None)
    
    :param label: The label to search for
    :returns: The memory table, parsed into a list of dicts. If the label
      parameter is given, returns a single entry as a dict, or None. False
      if there was a problem reading the table.
    """
    table = self.read_raw_memory_table()
    if table is False:
        return False
    
    if label is None:
        return self.parse_whole_memory_table(table)
    else:
        return self.search_raw_memory_table(table, label)
  
  #TODO: Refactor the idea of a "memory table" into a class
  
  ##############################################################################
  # Helper functions for interpreting and processing memory tables             #
  ##############################################################################
  
  @staticmethod
  def chunk_raw_memory_table(table):
    """Simple generator to split a raw memory table into 11-character entries
    
    :param table: string containing the raw memory table
    :yields: consecutive entries from the table
    """
    for i in xrange(0, len(table), 11):
      yield table[i:i+11]
      
  @classmethod
  def find_raw_entry(cls, table, label):
    """Searches for and returns the 11 character table entry corresponding to the label
    
    :param table: string containing the raw memory table
    :param label: the label to search for
    :returns: raw memory entry corresponding to the label
    """
    
    for entry in cls.chunk_raw_memory_table(table):
      if entry[0] == label:
        return entry
    return None
      
  @classmethod
  def parse_raw_entry(cls, entry):
    """Take a raw 11 character entry and parse it into a dict
      
    :param entry: the entry to parse
    :returns: the parsed result, as a dict
    """
    pattern = "(?P<label>[\x20-\x7F])(?P<type_char>[ABD])(?P<locked>[UL])(?P<size>[0-9a-fA-F]{4})(?P<Q>[0-9A-Fa-f]{4})"
    return cls._decorate_table_entry(re.match(pattern, entry).groupdict())

  @staticmethod
  def decorate_entry(entry):
    """Add processed attributes to a table entry dict, retrieved in parse_raw_entry
    
    This function adds some processed attributes to each table entry- it adds
    a human-readable data type, parses the size into height and width for dots
    pictures, and converts the size to an int. It returns a new entry, and
    leaves the old one untouched.
    
    :param entry: the table entry to decorate
    :returns: the decortated table entry
    """
    
    result = dict(entry.iteritems())
    
    #convert size from hex string to int
    result["size"] = int(result["size"], 16)
    
    #add type field. add height and width for dots.
    type_char = result["type_char"]
    if type_char == "A":
      result["type"] = "TEXT"
    elif type_char == "B":
      result["type"] = "STRING"
    elif type_char == "D":
      result["type"] = "DOTS"
      #additionally add height and width
      result["height"] = int(result["size"] / 256)
      result["width"] = result["size"] % 256
      
    return result

  @classmethod
  def parse_raw_memory_table(cls, table):
    """Takes a raw memory table and parses it into a list of dicts
    """
    return [cls.parse_raw_entry(entry) for entry in cls.chunk_raw_memory_table(table)]

  @classmethod
  def find_entry(cls, table, label):
    """Searches a raw memory table for an entry and parses the result
    """
    entry = cls.find_raw_entry(table, label)
    if entry is None:
        return None
    else:
        return cls.parse_raw_entry(entry)
    
    ############################################################################
    # Method summary:
    #   chunk_raw_memory table - takes raw table, returns raw entries
    #   find_raw_entry - chunk, then return specific raw entry
    #   parse_raw_entry - takes raw entry, returns parsed entry
    #     decorate_entry - helper to parse entries
    #   parse_raw_memory_table - chunk followed by parse
    #   find_entry - find followed by parse
    #
    #   read_raw_memory_table - read raw table from sign
    #   read_mempory_table - read followed by parse or find
    ############################################################################
