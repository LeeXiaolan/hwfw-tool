#!/usr/bin/env python
'''
Copyright (C) 2016 Xiaolan.Lee<LeeXiaolan@gmail.com>
License: GPLv2 (see LICENSE for details).
THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
'''

from __future__ import print_function
import logging
import os
import socket
import struct
import sys
import zlib

import docopt

__opt__ = '''Usage:
  %(prog)s unpack [-v... -r DIR] FILE
  %(prog)s pack [-v... -r DIR] FILE

Options:
  -r DIR, --root           Root directory, unpack to or pack from[default: .].
  -v, --verbose            Verbose mode.
'''

def crc32(data, start=0):
  return zlib.crc32(data, start)

def seqCrc32(seq, start=0):
  for i in seq:
    start = crc32(i, start)
  return start

class HuaweiFirmware(object):
  _HEADER_FILE = '.header'

  def open(self, path, noItemData=False):
    with open(path, 'rb') as f:
      data = f.read()
    self._loadFromString(data, noItemData)

  def _loadFromString(self, data, noItemData):
    mv = memoryview(data)
    offset = 0
    offset += self._parseHeader(data[offset:])
    if self.header.extraHeaderLength:
      offset += self._parseExtraHeader(data[offset:])
    offset += self._parseItemInfo(data, offset, noItemData)

  def _parseHeader(self, data):
    self.header = HuaweiFirmwareHeader()
    return self.header.loadFromString(data)

  def _parseExtraHeader(self, data):
    size = self.header.extraHeaderLength
    self.extraHeader = data[:size]
    return size

  def _parseItemInfo(self, data, offset, noItemData):
    totalLength = len(data)
    initialOffset = offset
    itemDataBegin = initialOffset + self.header.itemCount * HuaweiFirmwareItem._FORMAT.size
    self.items = []
    for i in xrange(self.header.itemCount):
      item, size = self._parseSingleItemInfo(data[offset:])
      offset += size
      if not noItemData:
        assert item.start >= itemDataBegin, 'Item data underflow.'
        assert item.end <= totalLength, 'Item data end overflow.'
        item.data = data[item.start:item.end]
      self.items.append(item)
    return offset - initialOffset

  def _parseSingleItemInfo(self, data):
    item = HuaweiFirmwareItem()
    size = item.loadInfo(data)
    return (item, size)

  def pack(self, directory, output):
    path = os.path.join(directory, self._HEADER_FILE)
    if not os.path.exists(path):
      logging.error('header file does not exist.')
      return 2
    self.open(path, noItemData=True)
    self.loadItemDataFromFile(directory)
    with open(output, 'wb') as f:
      f.write(self.toString(noItemData=False))

  def loadItemDataFromFile(self, directory):
    offset = (HuaweiFirmwareHeader._FORMAT.size 
        + self.header.extraHeaderLength
        + self.header.itemCount * HuaweiFirmwareItem._FORMAT.size
    )
    for item in self.items:
      item.loadDataFromFile(directory)
      item.start = offset
      offset += item.size

  def unpack(self, directory):
    if not os.path.exists(directory):
      os.makedirs(directory)
    return self.save(directory)

  def save(self, directory):
    with open(os.path.join(directory, self._HEADER_FILE), 'wb') as f:
      f.write(self.toString())
    for item in self.items:
      item.saveData(directory)

  def toString(self, noItemData=True):
    self.header.fileLength = (
        self.header._FORMAT.size 
        + self.header.itemCount * HuaweiFirmwareItem._FORMAT.size
        - 0x4c # FIXME: Can not find where does this bias come from.
    )
    strs = [
      self.header.toString()[20:], # Partial header used for calculate CRC32 value.
    ]
    if self.header.extraHeaderLength:
      strs.append(self.extraHeader)
      self.header.fileLength += len(self.extraHeader)
    data = []
    for item in self.items:
      strs.append(item.toString())
      data.append(item.data)
      self.header.fileLength += item.size
    # Convert to big endian.
    self.header.fileLength = socket.htonl(self.header.fileLength)

    # Update header CRC32 value.
    self.header.headerCrc = seqCrc32(strs)

    if not noItemData:
      strs.extend(data)
      # All data are present, now update file CRC32 value.
      strs[0] = self.header.toString()[12:]
      self.header.fileCrc = seqCrc32(strs)

    # Using the latest header with correct CRC32 value and file length.
    strs[0] = self.header.toString()
    return ''.join(strs)

  def getDotDirectory(self, directory):
    return os.path.join(directory, '.fw')

class HuaweiFirmwareHeader(object):
  _FORMAT = struct.Struct('<4sIiIiI3H6s')

  def loadFromString(self, data):
    size = self._FORMAT.size
    (
      self.magic,
      self.fileLength,
      self.fileCrc,
      self.headerSize,
      self.headerCrc,
      self.itemCount,
      dummy,
      self.extraHeaderLength,
      self.itemSize,
      dummy,
    ) = self._FORMAT.unpack(data[:size])
    return size

  def toString(self):
    return self._FORMAT.pack(
      self.magic,
      self.fileLength,
      self.fileCrc,
      self.headerSize,
      self.headerCrc,
      self.itemCount,
      0,
      self.extraHeaderLength,
      self.itemSize,
      '\0' * 6,
    )

class HuaweiFirmwareItem(object):
  _FORMAT = struct.Struct('<IiII256s80s2I')

  def loadInfo(self, data):
    size = self._FORMAT.size
    (
      self.seq,
      self.crc,
      self.start,
      self.size,
      self.name,
      self.typeName,
      self.policy,
      self.unknown,
    ) = self._FORMAT.unpack(data[:size])
    self.data = None
    return size

  @property
  def end(self):
    return self.start + self.size

  def toString(self):
    return self._FORMAT.pack(
      self.seq,
      self.crc,
      self.start,
      self.size,
      self.name,
      self.typeName,
      self.policy,
      self.unknown,
    )

  def saveData(self, directory):
    name = self.path
    path = name.lstrip(r'\/')
    path = os.path.join(directory, path)
    targetDirectory = os.path.dirname(path)
    if targetDirectory and not os.path.exists(targetDirectory):
        os.makedirs(targetDirectory)
    policyIndicator = 'x' if self.policy & 0x2 else ' '
    print('saving %s %s(%d)...' %  (
      policyIndicator,
      name,
      self.size,
    ))
    with open(path, 'wb') as f:
      f.write(self.data)

  def loadDataFromFile(self, directory):
    name = self.path
    path = name.lstrip(r'\/')
    path = os.path.join(directory, path)
    print('reading %s...' %  name)
    with open(path, 'rb') as f:
      self.data = f.read()
    self.update()

  def update(self):
    self.size = len(self.data)
    self.crc = crc32(self.data)

  @property
  def path(self):
    if self.name.startswith('file:'):
      return self.name[5:].rstrip('\0')
    elif self.name.startswith('flash:'):
      return os.path.join('flash', self.name[6:].rstrip('\0'))
    raise NotImplementedError(self.name.rstrip('\0'))

def unpack(opt):
  fw = HuaweiFirmware()
  fw.open(opt['FILE'])
  return fw.unpack(opt['--root'])

def pack(opt):
  fw = HuaweiFirmware()
  return fw.pack(opt['--root'], opt['FILE'])

def entry(opt):
  if opt['unpack']:
    return unpack(opt)
  elif opt['pack']:
    return pack(opt)
  else:
    return 1

def main():
  opt = docopt.docopt(__opt__ % {'prog': os.path.basename(sys.argv[0])})
  verbose = opt['--verbose']
  logging.getLogger().setLevel(getattr(logging, (
      'ERROR',
      'WARNING',
      'INFO',
      'DEBUG',
  )[min(verbose, 3)]))
  logging.debug(opt)
  sys.exit(entry(opt))

if __name__ == '__main__':
  main()
