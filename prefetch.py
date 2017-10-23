# Copyright (C) 2013 Dave Lassalle (@superponible) <dave@superponible.com>
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""
@author:       Dave Lassalle (@superponible)
@license:      GNU General Public License 2.0 or later
@contact:      dave@superponible.com
"""

# Information for this script taken from http://www.forensicswiki.org/wiki/Windows_Prefetch_File_Format

import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.common as common
import volatility.plugins.filescan as filescan
from volatility.renderers import TreeGrid
import volatility.scan as scan
import volatility.utils as utils
import os
import struct
from ctypes import *

PF_file_XP = {
    'PF_HEADER': [ 0x9C, {
        'Version': [ 0x0, ['unsigned int']],
        'Magic': [ 0x4, ['String', dict(length = 4)]],
        'Version2': [0x8, ['unsigned int']],
        'Length': [ 0xc, ['unsigned int']],
        'Name': [0x10, ['NullString', dict(length = 60)]],
        'Hash': [ 0x4c, ['unsigned int']],
        'NtosBoot': [ 0x50, ['unsigned int']],
        'SecAOff': [ 0x54, ['unsigned int']],
        'SecAEntries': [ 0x58, ['unsigned int']],
        'SecBOff': [ 0x5c, ['unsigned int']],
        'SecBEntries': [ 0x60, ['unsigned int']],
        'SecCOff': [ 0x64, ['unsigned int']],
        'SecCLength': [ 0x68, ['unsigned int']],
        'SecDOff': [ 0x6c, ['unsigned int']],
        'SecDEntries': [ 0x70, ['unsigned int']],
        'LastExecTime': [0x78, ['WinTimeStamp', dict(is_utc = True)]],
        'TimesExecuted': [0x90, ['unsigned int']],
    }]
}

PF_file_Win7 = {
    'PF_HEADER': [ 0x9C, {
        'Version': [ 0x0, ['unsigned int']],
        'Magic': [ 0x4, ['String', dict(length = 4)]],
        'Version2': [0x8, ['unsigned int']],
        'Length': [ 0xc, ['unsigned int']],
        'Name': [0x10, ['NullString', dict(length = 60)]],
        'Hash': [ 0x4c, ['unsigned int']],
        'NtosBoot': [ 0x50, ['unsigned int']],
        'SecAOff': [ 0x54, ['unsigned int']],
        'SecAEntries': [ 0x58, ['unsigned int']],
        'SecBOff': [ 0x5c, ['unsigned int']],
        'SecBEntries': [ 0x60, ['unsigned int']],
        'SecCOff': [ 0x64, ['unsigned int']],
        'SecCLength': [ 0x68, ['unsigned int']],
        'SecDOff': [ 0x6c, ['unsigned int']],
        'SecDEntries': [ 0x70, ['unsigned int']],
        'LastExecTime': [0x80, ['WinTimeStamp', dict(is_utc = True)]],
        'TimesExecuted': [0x98, ['unsigned int']],
    }]
}

PF_file_Win81 = {
    'PF_HEADER': [ 0x9C, {
        'Version': [ 0x0, ['unsigned int']],
        'Magic': [ 0x4, ['String', dict(length = 4)]],
        'Version2': [0x8, ['unsigned int']],
        'Length': [ 0xc, ['unsigned int']],
        'Name': [0x10, ['NullString', dict(length = 60)]],
        'Hash': [ 0x4c, ['unsigned int']],
        'NtosBoot': [ 0x50, ['unsigned int']],
        'SecAOff': [ 0x54, ['unsigned int']],
        'SecAEntries': [ 0x58, ['unsigned int']],
        'SecBOff': [ 0x5c, ['unsigned int']],
        'SecBEntries': [ 0x60, ['unsigned int']],
        'SecCOff': [ 0x64, ['unsigned int']],
        'SecCLength': [ 0x68, ['unsigned int']],
        'SecDOff': [ 0x6c, ['unsigned int']],
        'SecDEntries': [ 0x70, ['unsigned int']],
        'LastExecTime': [0x80, ['WinTimeStamp', dict(is_utc = True)]],
        'LastExecTime2': [0x88, ['WinTimeStamp', dict(is_utc = True)]],
        'LastExecTime3': [0x90, ['WinTimeStamp', dict(is_utc = True)]],
        'LastExecTime4': [0x98, ['WinTimeStamp', dict(is_utc = True)]],
        'LastExecTime5': [0xA0, ['WinTimeStamp', dict(is_utc = True)]],
        'LastExecTime6': [0xA8, ['WinTimeStamp', dict(is_utc = True)]],
        'LastExecTime7': [0xB0, ['WinTimeStamp', dict(is_utc = True)]],
        'LastExecTime8': [0xB8, ['WinTimeStamp', dict(is_utc = True)]],
        'TimesExecuted': [0xD0, ['unsigned int']],
    }]
}

# Define ms_decompress() Variables
MSCOMP_OK = 0
MSCOMP_DATA_ERROR = -3
XpressHuffman = 4
TerminateBlock = '\x00\x00'

def cast_ptr(buf):
    if isinstance(buf, bytearray):
        buf = (c_ubyte * len(buf)).from_buffer(buf)
    return cast(buf, c_void_p)

class HashGenerator(object):
    def __init__(self, filename):
        # @filename: full kernel path to a file in upper case
        self.filename = filename.encode('utf-16-le')

    def ssca_xp_hash_function(self):
        # https://github.com/libyal/libscca/blob/master/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc#51-scca-xp-hash-function
        hash_value = 0
        for character in self.filename:
            hash_value = ((hash_value * 37) + ord(character)) % 0x100000000

        hash_value = (hash_value * 314159269) % 0x100000000

        if hash_value > 0x80000000:
            hash_value = 0x100000000 - hash_value

        return (abs(hash_value) % 1000000007) % 0x100000000

    def ssca_vista_hash_function(self):
        # https://github.com/libyal/libscca/blob/master/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc#52-scca-vista-hash-function
        hash_value = 314159
        for character in self.filename:
            hash_value = ((hash_value * 37) + ord(character)) % 0x100000000

        return hash_value

    def ssca_2008_hash_function(self):
        # https://github.com/libyal/libscca/blob/master/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc#53-scca-2008-hash-function
        hash_value = 314159
        filename_index = 0
        filename_length = len(self.filename)

        while filename_index + 8 < filename_length:
            character_value = ord(self.filename[filename_index + 1]) * 37
            character_value += ord(self.filename[filename_index + 2])
            character_value *= 37
            character_value += ord(self.filename[filename_index + 3])
            character_value *= 37
            character_value += ord(self.filename[filename_index + 4])
            character_value *= 37
            character_value += ord(self.filename[filename_index + 5])
            character_value *= 37
            character_value += ord(self.filename[filename_index + 6])
            character_value *= 37
            character_value += ord(self.filename[filename_index]) * 442596621
            character_value += ord(self.filename[filename_index + 7])

            hash_value = ((character_value - (hash_value * 803794207)) %
                          0x100000000)

            filename_index += 8

        while filename_index < filename_length:
            hash_value = (((37 * hash_value) + ord(self.filename[filename_index])) %
                          0x100000000)

            filename_index += 1

        return hash_value

class PFTYPES_XP(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 5}
    def modification(self, profile):
        profile.vtypes.update(PF_file_XP)

class PFTYPES_W7(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 0 or x == 1} # Vista or Win7
    def modification(self, profile):
        profile.vtypes.update(PF_file_Win7)

class PFTYPES_W81(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 2 or x == 3} # Win8 or 8.1
    def modification(self, profile):
        profile.vtypes.update(PF_file_Win81)

# https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/overlays/windows/win10.py
class PFTYPES_W10(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows',
                  'major': lambda x: x == 6,
                  'minor': lambda x: x == 4} # Win10
    def modification(self, profile):
        profile.vtypes.update(PF_file_Win81) # Win10 is similar to Win8.1

class PrefetchScanner(scan.BaseScanner):
    def __init__(self, config, needles = None):
        self.config = config
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self)
        self.file_num = 0

    def load_libmscompression(self):
        if os.name == 'nt':
            if sizeof(c_void_p) == 8:
                lib_names = ('MSCompression','MSCompression64')
            else:
                lib_names = ('MSCompression',)
        else:
            lib_names = ('libMSCompression.so',)

        for lib_name in lib_names:
            try:
                self.lib = cdll.LoadLibrary(lib_name)
                self.lib.ms_decompress.restype = c_int
                self.lib.ms_decompress.argtypes = [c_int, c_void_p, c_size_t, c_void_p, POINTER(c_size_t)]
            except OSError:
                debug.error("Can't load MSCompression Library. Please get it from https://github.com/coderforlife/ms-compress .")

    def mam_decompress(self, mam_data):
        # https://github.com/libyal/libscca/blob/master/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc#3-compressed-prefetch-file---mam-file-format
        decomp_len = struct.unpack("<L", mam_data[4:8])[0] # 'Decompressed Length Field'

        if decomp_len <= 1024 * 1024: # return if decomp_len is over 1MB.
            decompressed_data = bytearray(decomp_len)
        else:
            return MSCOMP_DATA_ERROR

        compressed_data = mam_data[8:] # Jump 'MAM\x04' + 'Decompressed Length Field'
        for idx in xrange(256, 4096): # 'Huffman Table' = 256 bytes
            buff = compressed_data[idx:idx+2]
            if buff == TerminateBlock:
                result = self.lib.ms_decompress(XpressHuffman, cast_ptr(compressed_data[:idx+2]), c_size_t(idx+1), cast_ptr(decompressed_data), byref(c_size_t(decomp_len)))

                if result == MSCOMP_OK:
                    return decompressed_data

        return MSCOMP_DATA_ERROR

    def carve(self, address_space, offset):
        pf_buff = address_space.read(offset-4, 256)
        bufferas = addrspace.BufferAddressSpace(self.config, data = pf_buff)
        self.pf_header = obj.Object('PF_HEADER', vm = bufferas, offset = 0)

        return self.pf_header

    def carve_mam(self, address_space, offset, dump_dir):
        mam_buff = address_space.read(offset, 4096)

        mam_file = os.path.abspath(os.path.join(dump_dir, "mam-pf-{0:04d}.pf".format(self.file_num)))
        with open(mam_file, 'wb') as f:
            try:
                f.write(mam_buff)
                self.file_num += 1
            except IOError as e:
                debug.error("Cannot write to {0} : {1}".format(mam_file, e))

        mam_buff = self.mam_decompress(mam_buff)
        if mam_buff < 0:
            return mam_buff

        bufferas = addrspace.BufferAddressSpace(self.config, data = mam_buff)
        self.pf_header = obj.Object('PF_HEADER', vm = bufferas, offset = 0)

        return self.pf_header

    def dedup(self, pf_headers):
        """ Yields a unique list of prefetch entries from all PF_HEADERs """
        unique_entries = []
        for pf_header in pf_headers:
            new = {pf_header:
                    ('{0}'.format(pf_header.Name),
                     '{0}'.format(pf_header.Hash),
                     '{0}'.format(pf_header.LastExecTime),
                     '{0}'.format(pf_header.TimesExecuted),
                     '{0}'.format(pf_header.Length))
                    }

            if not new in unique_entries:
                unique_entries.append(new)

        for unique_entry in unique_entries:
            for header, uniqued_data in unique_entry.iteritems():
                yield header

    def is_valid(self):
        """ Checks of a prefetch header structure is valid """

        # https://github.com/libyal/libscca/blob/master/documentation/Windows%20Prefetch%20File%20%28PF%29%20format.asciidoc#411-format-version
        # 17 = XP/2003
        # 23 = Vista/2008/7/2012
        # 26 = 8.1
        # 30 = 10
        if self.pf_header.Version != 30 and self.pf_header.Version != 26 and \
           self.pf_header.Version != 23 and self.pf_header.Version != 17:
            return
        if self.pf_header.Version2 != 15 and self.pf_header.Version2 != 17:
            return
        if self.pf_header.NtosBoot != 0 and self.pf_header.NtosBoot != 1:
            return
        if self.pf_header.Length < 1 or self.pf_header.Length > 99999999:
            return
        if not ('%X' % self.pf_header.Hash).isalnum():
            return
        if self.pf_header.LastExecTime == 0:
            return
        if self.pf_header.TimesExecuted > 99999999:
            return

        return True

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

class DirectoryEnumerator(filescan.FileScan):
    """ Enumerates all unique directories from FileScan """

    def __init__(self, config):
        filescan.FileScan.__init__(self, config)

    def scan(self):
        # Enumerate all available file paths
        directories = []
        scanner = filescan.FileScan(self._config)
        for fobj in scanner.calculate():
            fpath = "{0}".format(fobj.file_name_with_device() or '')
            if fpath:
                path = fpath.upper().rsplit('\\', 1)[0]
                if not path in directories:
                    directories.append(path)

        return directories

class PrefetchParser(common.AbstractWindowsCommand):
    """ Scans for and parses potential Prefetch files """

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                (profile.metadata.get('major') == 5 or
                 profile.metadata.get('major') == 6))

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('FULL_PATHS', default = False,
                          help = 'Print the full path the Prefetch file translates to, if possible.',
                          action = "store_true")
        config.add_option('MAM-DIR', default = './mam-pf/',
                          help = 'Directory which to dump MAM Compressed Prefetch.')

    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        if not self.is_valid_profile(address_space.profile):
            debug.error("This command does not support the selected profile.")

        scanner = PrefetchScanner(config = self._config, needles = ['SCCA'])
        scanner_mam = PrefetchScanner(config = self._config, needles = ['MAM\x04'])
        pf_headers = []

        if(address_space.profile.metadata.get('major') == 6 and address_space.profile.metadata.get('minor') == 4): # Win10
            scanner_mam.load_libmscompression()
            debug.debug("Scanning for MAM compressed data, this can take a while.............")
            if not os.path.isdir(self._config.MAM_DIR):
                debug.error(self._config.MAM_DIR + " is not a directory. Please specify a mam dump directory (--mam-dir)")

            for offset in scanner_mam.scan(address_space):
                pf_header = scanner_mam.carve_mam(address_space, offset, self._config.MAM_DIR)
                if pf_header > 0 and scanner_mam.is_valid():
                    pf_headers.append(pf_header)

        debug.debug("Scanning for Prefetch files, this can take a while.............")
        for offset in scanner.scan(address_space):
            pf_header = scanner.carve(address_space, offset)
            if scanner.is_valid():
                pf_headers.append(pf_header)

        # This list may have duplicate pf_header entries since
        #   we're not doing unique validation, just scanning.
        # Uniquing makes sense for reducing repetetive entries
        for unique_pf_entry in scanner.dedup(pf_headers):
            yield unique_pf_entry

    def unified_output(self, data):
        """This standardizes the output formatting"""

        row = [
                ("Prefetch File", str),
                ("Execution Time", str),
                ("Times", str),
                ("Size", str),
            ]

        if self._config.FULL_PATHS:
            row.append(("File Path", str))

        return TreeGrid(row, self.generator(data))

    def generator(self, data):
        """This yields data according to the unified output format"""

        if self._config.FULL_PATHS:
            directory_scanner = DirectoryEnumerator(self._config)
            directories = directory_scanner.scan()

        for pf_header in data:
            pf_file = '{0}-{1:X}.pf'.format(pf_header.Name, pf_header.Hash)
            if self._config.FULL_PATHS:
                for path in directories:
                    full_path = "{0}\\{1}".format(path, pf_header.Name)
                    if pf_header.Version == 17:
                        pf_hash = HashGenerator(full_path).ssca_xp_hash_function()
                    elif pf_header.Version == 23:
                        pf_hash = HashGenerator(full_path).ssca_vista_hash_function()
                    elif pf_header.Version == 26 or pf_header.Version == 30:
                        pf_hash = HashGenerator(full_path).ssca_2008_hash_function()

                    if "{0}".format(pf_hash) == "{0}".format(pf_header.Hash):
                        break

                yield (0, [str(pf_file),
                            str(pf_header.LastExecTime),
                            str(pf_header.TimesExecuted),
                            str(pf_header.Length),
                            str(full_path),
                        ])
            else:
                yield (0, [str(pf_file),
                            str(pf_header.LastExecTime),
                            str(pf_header.TimesExecuted),
                            str(pf_header.Length),
                        ])

            if pf_header.Version == 26 or pf_header.Version == 30:
                lastexectimes = [pf_header.LastExecTime2, pf_header.LastExecTime3, pf_header.LastExecTime4, pf_header.LastExecTime5, pf_header.LastExecTime6, pf_header.LastExecTime7, pf_header.LastExecTime8]
                for i in range(min(8, int(pf_header.TimesExecuted))-1):
                    if self._config.FULL_PATHS:
                        yield (0, [str(pf_file),
                                    str(lastexectimes[i]),
                                    str(pf_header.TimesExecuted),
                                    str(pf_header.Length),
                                    str(full_path),
                                ])
                    else:
                        yield (0, [str(pf_file),
                                    str(lastexectimes[i]),
                                    str(pf_header.TimesExecuted),
                                    str(pf_header.Length),
                                ])

    def render_text(self, outfd, data):
        """Renders the Prefetch entries as text"""

        headers = [
                    ("Prefetch File", "42"),
                    ("Execution Time", "28"),
                    ("Times", "5"),
                    ("Size", "8"),
                ]

        if self._config.FULL_PATHS:
            headers.append(("File Path", ""))
            directory_scanner = DirectoryEnumerator(self._config)
            directories = directory_scanner.scan()

        self.table_header(outfd, headers)

        for pf_header in data:
            pf_file = '{0}-{1:X}.pf'.format(pf_header.Name, pf_header.Hash)
            if self._config.FULL_PATHS:
                # Iterate prefetch files previously found & compare their
                #   file path hash to the ones generated
                full_path = ''
                for path in directories:
                    full_path = "{0}\\{1}".format(path, pf_header.Name)
                    if pf_header.Version == 17:
                        pf_hash = HashGenerator(full_path).ssca_xp_hash_function()
                    elif pf_header.Version == 23:
                        pf_hash = HashGenerator(full_path).ssca_vista_hash_function()
                    elif pf_header.Version == 26 or pf_header.Version == 30:
                        pf_hash = HashGenerator(full_path).ssca_2008_hash_function()

                    if "{0}".format(pf_hash) == "{0}".format(pf_header.Hash):
                        break

                self.table_row(outfd,
                                pf_file,
                                pf_header.LastExecTime,
                                pf_header.TimesExecuted,
                                pf_header.Length,
                                full_path)
            else:
                self.table_row(outfd,
                                pf_file,
                                pf_header.LastExecTime,
                                pf_header.TimesExecuted,
                                pf_header.Length)

            if pf_header.Version == 26 or pf_header.Version == 30:
                lastexectimes = [pf_header.LastExecTime2, pf_header.LastExecTime3, pf_header.LastExecTime4, pf_header.LastExecTime5, pf_header.LastExecTime6, pf_header.LastExecTime7, pf_header.LastExecTime8]
                for i in range(min(8, int(pf_header.TimesExecuted))-1):
                    if self._config.FULL_PATHS:
                        self.table_row(outfd, "", lastexectimes[i], "", "", full_path)
                    else:
                        self.table_row(outfd, "", lastexectimes[i], "", "")
