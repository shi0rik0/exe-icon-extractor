from __future__ import annotations
from typing import BinaryIO, Union
import sys

RT_ICON = 3
RT_GROUP_ICON = 14


class Directory:
    id_or_name: Union[int, str]
    children_directories: list[Directory]
    children_files: list[File]

    def __init__(self):
        self.id_or_name = 0
        self.children_directories = []
        self.children_files = []


class File:
    id_or_name: Union[int, str]
    data: bytes


def read_uint(file: BinaryIO, size: int) -> int:
    b = file.read(size)
    return int.from_bytes(b, 'little')


def parse_rsrc(rsrc: bytes, va: int) -> Directory:

    def parse_file_entry(pos: int, id_or_name: Union[int, str]) -> File:
        f = File()
        f.id_or_name = id_or_name
        rva = int.from_bytes(rsrc[pos:pos + 4], 'little')
        size = int.from_bytes(rsrc[pos + 4:pos + 8], 'little')
        f.data = rsrc[rva - va:rva - va + size]
        return f

    def parse_directory_entry(pos: int, id_or_name: Union[int,
                                                          str]) -> Directory:
        d = Directory()
        d.id_or_name = id_or_name
        num_name_entries = int.from_bytes(rsrc[pos + 12:pos + 14], 'little')
        if num_name_entries:
            raise 0
        num_id_entries = int.from_bytes(rsrc[pos + 14:pos + 16], 'little')
        for i in range(num_id_entries):
            j = pos + 16 + i * 8
            int_id = int.from_bytes(rsrc[j:j + 4], 'little')
            offset = rsrc[j + 4:j + 8]
            if offset[-1] >> 7:
                offset = offset[:-1] + int.to_bytes(offset[-1] & ~(1 << 7))
                offset = int.from_bytes(offset, 'little')
                d.children_directories.append(
                    parse_directory_entry(offset, int_id))
            else:
                offset = int.from_bytes(offset, 'little')
                d.children_files.append(parse_file_entry(offset, int_id))
        return d

    return parse_directory_entry(0, 0)


def get_files(dir: Directory) -> list[File]:
    a = []

    def f(dir: Directory):
        a.extend(dir.children_files)
        for i in dir.children_directories:
            f(i)

    f(dir)
    return a


def get_files2(dir: Directory) -> list[tuple[File, list[Union[int, str]]]]:
    a = []

    def f(dir: Directory, parents: list[Union[int, str]]):
        parents.append(dir.id_or_name)
        for i in dir.children_files:
            a.append((i, parents.copy()))
        for i in dir.children_directories:
            f(i, parents.copy())

    f(dir, [])
    return a


def parse_group_icon(dir: Directory) -> dict[int, bytes]:
    d = {}
    files = get_files(dir)
    for f in files:
        data = f.data
        count = int.from_bytes(data[4:6], 'little')
        for i in range(count):
            j = 6 + i * 14
            id_ = int.from_bytes(data[j + 12:j + 14], 'little')
            d[id_] = data[j:j + 12]
        return d


def main():
    with open(sys.argv[1], 'rb') as f:
        f.seek(0x3c)
        nt_header_offset = read_uint(f, 4)
        f.seek(nt_header_offset)
        if f.read(4) != b'PE\x00\x00':
            raise 0
        f.seek(2, 1)
        num_sections = read_uint(f, 2)
        f.seek(16, 1)
        magic = f.read(2)
        if magic == b'\x0b\x01':
            f.seek(222, 1)
        elif magic == b'\x0b\x02':
            f.seek(238, 1)
        else:
            raise 0
        for _ in range(num_sections):
            name = f.read(8)
            if name == b'.rsrc\x00\x00\x00':
                break
            f.seek(32, 1)
        else:
            raise 0
        f.seek(4, 1)
        va = read_uint(f, 4)
        size_of_rsrc = read_uint(f, 4)
        pos_of_rsrc = read_uint(f, 4)
        f.seek(pos_of_rsrc)
        rsrc = f.read(size_of_rsrc)
        root_dir = parse_rsrc(rsrc, va)
        for i in root_dir.children_directories:
            if i.id_or_name == RT_GROUP_ICON:
                group_icon = parse_group_icon(i)
                break
        else:
            raise 0
        for i in root_dir.children_directories:
            if i.id_or_name == RT_ICON:
                files = get_files2(i)
                for j in files:
                    icon_id = j[1][-1]
                    header = bytes([
                        0x00, 0x00, 0x01, 0x00, 0x01, 0x00
                    ]) + group_icon[icon_id] + bytes([0x16, 0x00, 0x00, 0x00])

                    with open(f'{icon_id}.ico', 'wb') as f:
                        f.write(header)
                        f.write(j[0].data)
                break
        else:
            raise 0


if __name__ == '__main__':
    main()
