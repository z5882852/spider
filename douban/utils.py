import base64
import struct
import math
# 这里提示找不到_BinaryPlistParser，但是不影响运行
from plistlib import FMT_BINARY, _BinaryPlistParser, _undefined
import plistlib
import xxhash
from Crypto.Cipher import ARC4


# 重写_read_object方法
def _read_object(self, ref):
    result = self._objects[ref]
    if result is not _undefined:
        return result

    offset = self._object_offsets[ref]
    self._fp.seek(offset)
    token = self._fp.read(1)[0]
    tokenH, tokenL = token & 0xF0, token & 0x0F

    if token == 0x00:
        result = None

    elif token == 0x08:
        result = False

    elif token == 0x09:
        result = True

    elif token == 0x0f:
        result = b''

    elif tokenH == 0x10:  # int
        result = int.from_bytes(self._fp.read(1 << tokenL),
                                'big', signed=tokenL >= 3)

    elif token == 0x22:  # real
        result = struct.unpack('>f', self._fp.read(4))[0]

    elif token == 0x23:  # real
        result = struct.unpack('>d', self._fp.read(8))[0]

    elif tokenH == 0x40:  # ascii string
        s = self._get_size(tokenL)
        result = self._fp.read(s).decode('ascii')
        result = result

    elif tokenH == 0x50:  # unicode string
        s = self._get_size(tokenL)
        result = self._fp.read(s * 2).decode('utf-16be')

    elif tokenH == 0xA0:  # array
        s = self._get_size(tokenL)
        obj_refs = self._read_refs(s)
        result = []
        self._objects[ref] = result
        result.extend(self._read_object(x) for x in obj_refs)

    elif tokenH == 0xD0:  # dict
        s = self._get_size(tokenL)
        key_refs = self._read_refs(s)
        obj_refs = self._read_refs(s)
        result = self._dict_type()
        self._objects[ref] = result
        for k, o in zip(key_refs, obj_refs):
            result[self._read_object(k)] = self._read_object(o)

    self._objects[ref] = result
    return result


# 由于豆瓣修改了bplist的解析方式，所以这里重写_read_object方法
_BinaryPlistParser._read_object = _read_object


def encrypt(encoded_data):
    """
    解密Data内容
    @param encoded_data: “window.__DATA__”的值
    """
    i = 16
    a = base64.b64decode(encoded_data)
    s = math.floor((len(a) - 2 * i) / 3)
    u = a[s:s + i]
    a = a[0:s] + a[s + i:]
    c = xxhash.xxh64_hexdigest(bytes(u), 41405)
    arc = ARC4.new(c.encode())
    data = arc.encrypt(a)
    return plistlib.loads(data, fmt=FMT_BINARY)


def parse(data):
    """
    解析解密后的数据
    :param data: 解密后的Data
    """
    def getRealUID(index):
        p = {
            'start': 2,
            'end': 7
        }
        if index >= p.get('start'):
            e = p.get('end') - p.get('start')
            if index < p['end']:
                return index + e
            if index < p['end'] + e:
                return index - e
        return index

    def n(e):
        if len(e) == 1 and 'j' in e:
            return o(e['j'])
        if "k" in e:
            z_list = e.get('z')
            k_list = e.get('k')
            if z_list:
                result = {o(z_list[i]): r(k_list[i]) for i in range(len(z_list))}
            else:
                result = [o(item) for item in k_list]
            return result

        return {key: r(value) for key, value in e.items()}

    def r(tt):
        if isinstance(tt, dict):
            return n(tt)
        elif isinstance(tt, list):
            return list(map(lambda e: r(e), tt))
        else:
            return tt

    def o(e):
        return r(data[getRealUID(e)])
    return o(getRealUID(4))

