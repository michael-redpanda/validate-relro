#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
import sys

OBJDUMP_DYN_REL_ENTRIES = 'objdump -R {binary}'
PROGRAM_HEADERS_PATTERN = 'readelf -l {binary}'
SECTION_HEADERS_PATTERN = 'readelf -S {binary}'

OBJDUMP_REGEX = r'^(?P<offset>[0-9a-fA-F]{16})\s+(?P<type>\w+)\s+(?P<value>[\w*+@]+)'
PROGRAM_HEADER_REGEX = r'^\s+(?P<type>\w+)\s+0x(?P<offset>[0-9a-fA-F]{16}) 0x(?P<virtaddr>[0-9a-fA-F]{16}) 0x(?P<physaddr>[0-9a-fA-F]{16})\s*\n\s+0x(?P<filesize>[0-9a-fA-F]{16}) 0x(?P<memsize>[0-9a-fA-F]{16})'
SECTION_HEADER_REGEX = r'^\s+\[\s?(?P<number>\d+)\]\s+(?P<name>[\w.]+)\s+(?P<type>\w+)\s+(?P<address>[0-9a-fA-F]{16})\s+(?P<offset>[0-9a-fA-F]{8})\s*\n\s+(?P<size>[0-9a-fA-F]{16})\s+(?P<entsize>[0-9a-fA-F]{16})\s+\w*\s+\d+\s+\d+\s+(?P<align>\d+)'


class DynRelocationSymbol(dict):

    def __init__(self, match):
        self._offset = int(match[0], 16)
        self._type = match[1]
        self._value = match[2]
        dict.__init__(self,
                      offset=self._offset,
                      type=self._type,
                      value=self._value)

    def __repr__(self):
        return json.dumps(dict(self.__dict__))

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def type(self) -> str:
        return self._type

    @property
    def value(self) -> str:
        return self._value


class ProgramHeader(dict):

    def __init__(self, match):
        self._type = match[0]
        self._offset = int(match[1], 16)
        self._virtual_address = int(match[2], 16)
        self._physical_address = int(match[3], 16)
        self._file_size = int(match[4], 16)
        self._mem_size = int(match[5], 16)
        dict.__init__(self,
                      type=self._type,
                      offset=self._offset,
                      virtual_address=self._virtual_address,
                      physical_address=self._physical_address,
                      file_size=self._file_size,
                      memory_size=self._mem_size)

    def __repr__(self):
        return json.dumps(self.__dict__)

    @property
    def type(self) -> str:
        return self._type

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def virtual_address(self) -> int:
        return self._virtual_address

    @property
    def physical_address(self) -> int:
        return self._physical_address

    @property
    def file_size(self) -> int:
        return self._file_size

    @property
    def memory_size(self) -> int:
        return self._mem_size


class SectionHeader(dict):

    def __init__(self, match):
        self._number = int(match[0])
        self._name = match[1]
        self._type = match[2]
        self._address = int(match[3], 16)
        self._offset = int(match[4], 16)
        self._size = int(match[5], 16)
        self._entry_size = int(match[6], 16)
        self._align = int(match[7])
        dict.__init__(self,
                      number=self._number,
                      header=dict(name=self._name,
                                  type=self._type,
                                  address=self._address,
                                  offset=self._offset,
                                  size=self._size,
                                  entry_size=self._entry_size,
                                  align=self._align))

    def __repr__(self):
        return json.dumps(self.__dict__)

    @property
    def number(self) -> int:
        return self._number

    @property
    def name(self) -> str:
        return self._name

    @property
    def type(self) -> str:
        return self._type

    @property
    def address(self) -> int:
        return self._address

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def size(self) -> int:
        return self._size

    @property
    def entry_size(self) -> int:
        return self._entry_size

    @property
    def align(self) -> int:
        return self._align


class Result(object):

    def __init__(self, binary):
        self._binary = binary
        self._relro_header = None
        self._got_plt_section = None
        self._dyn_relo_symbols: [DynRelocationSymbol] = []

    def __repr__(self):
        got_plt_result = None
        if self._got_plt_section is not None:
            got_plt_result = dict(
                got_plt_in_relro=self.got_plt_in_relro_header(),
                got_plt_section=self._got_plt_section,
                got_plt_symbols=self.dyn_relo_symbols_in_got_plt())
        res = dict(binary=self._binary,
                   results=dict(relro_header=self._relro_header,
                                got_plt=got_plt_result))
        return json.dumps(res)

    @property
    def dyn_relo_symbols(self) -> [DynRelocationSymbol]:
        return self._dyn_relo_symbols

    @dyn_relo_symbols.setter
    def dyn_relo_symbols(self, val: [DynRelocationSymbol]):
        self._dyn_relo_symbols = val

    @property
    def got_plt_exists(self) -> bool:
        return self._got_plt_section is not None

    @property
    def relro_header(self) -> ProgramHeader:
        return self._relro_header

    @relro_header.setter
    def relro_header(self, hdr: ProgramHeader):
        self._relro_header = hdr

    @property
    def got_plt_section(self) -> SectionHeader:
        return self._got_plt_section

    @got_plt_section.setter
    def got_plt_section(self, val: SectionHeader):
        self._got_plt_section = val

    def got_plt_in_relro_header(self) -> bool:
        return self._got_plt_in_section_header()

    def got_plt_dyns_not_in_relro(self) -> [DynRelocationSymbol]:
        return [
            x for x in self.dyn_relo_symbols_in_got_plt()
            if not symbol_in_program(x, self._relro_header)
        ]

    def dyn_relo_symbols_in_got_plt(self) -> [DynRelocationSymbol]:
        return [
            x for x in self._dyn_relo_symbols
            if symbol_in_section(x, self._got_plt_section)
        ]

    def dyn_relo_symbols_not_in_relro(self) -> [DynRelocationSymbol]:
        return [
            x for x in self._dyn_relo_symbols
            if not symbol_in_program(x, self._relro_header)
        ]

    def _got_plt_in_section_header(self) -> bool:
        if not self.got_plt_exists or self.relro_header is None:
            raise RuntimeError('Missing Relro Header or .got.plt section')

        return is_section_in_header(self._got_plt_section, self._relro_header)


def execute_command(cmd, **kwargs) -> str:
    result = subprocess.run(cmd.format(**kwargs).split(' '),
                            capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to execute '{cmd}': rc {result.returncode}, stderr: \"{result.stderr}\""
        )
    return result.stdout.decode('utf-8')


def find_dynamic_relocation_symbols(binary_file) -> [DynRelocationSymbol]:
    result = execute_command(
        OBJDUMP_DYN_REL_ENTRIES.format(binary=binary_file))
    regex = re.compile(OBJDUMP_REGEX, re.MULTILINE)
    rv = []
    for i in regex.findall(result):
        rv.append(DynRelocationSymbol(i))

    return rv


def find_program_headers(binary_file) -> [ProgramHeader]:
    result = execute_command(
        PROGRAM_HEADERS_PATTERN.format(binary=binary_file))
    regex = re.compile(PROGRAM_HEADER_REGEX, re.MULTILINE)
    rv = []
    for i in regex.findall(result):
        rv.append(ProgramHeader(i))

    return rv


def find_section_headers(binary_file) -> [SectionHeader]:
    result = execute_command(
        SECTION_HEADERS_PATTERN.format(binary=binary_file))
    regex = re.compile(SECTION_HEADER_REGEX, re.MULTILINE)
    rv = []
    for i in regex.findall(result):
        rv.append(SectionHeader(i))

    return rv


def is_section_in_header(section: SectionHeader,
                         header: ProgramHeader) -> bool:
    start_section = section.address
    end_section = start_section + section.size

    start_header = header.virtual_address
    end_header = start_header + header.memory_size

    return start_section >= start_header and end_section <= end_header


def parse_args():
    parser = argparse.ArgumentParser(
        description='Program used to validate all symbols are RELRO')
    parser.add_argument('binary', help='Path to binary to examine')
    return parser.parse_args()


def symbol_in_program(symbol: DynRelocationSymbol,
                      program: ProgramHeader) -> bool:
    program_start = program.virtual_address
    program_end = program_start + program.memory_size

    return program_start <= symbol.offset <= program_end


def symbol_in_section(symbol: DynRelocationSymbol,
                      section: SectionHeader) -> bool:
    section_start = section.address
    section_end = section_start + section.size

    return section_start <= symbol.offset <= section_end


def main():
    args = parse_args()
    res = Result(args.binary)
    program_headers = find_program_headers(args.binary)
    relro_header = next((i for i in program_headers if i.type == 'GNU_RELRO'),
                        None)
    if relro_header is None:
        raise RuntimeError('Failed to find GNU_RELRO program header')

    res.relro_header = relro_header

    section_headers = find_section_headers(args.binary)
    got_plt = next((i for i in section_headers if i.name == '.got.plt'), None)
    if got_plt is not None:
        res.got_plt_section = got_plt

    res.dyn_relo_symbols = find_dynamic_relocation_symbols(args.binary)

    print(f'{res}')


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f'Failed to execute program: {e}')
        sys.exit(1)
