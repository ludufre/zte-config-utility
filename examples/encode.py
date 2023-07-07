"""Encode config.xml into config.bin"""
import struct
import argparse
from types import SimpleNamespace
import zcu

from zcu.xcryptors import Xcryptor, CBCXcryptor
from zcu.known_keys import run_any_keygen


def main():
    """the main function"""
    parser = argparse.ArgumentParser(description='Encode config.bin for ZTE Routers',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('infile', type=argparse.FileType('rb'),
                        help='Raw configuration file e.g. config.xml')
    parser.add_argument('outfile', type=argparse.FileType('wb'),
                        help='Output file, e.g. config.bin')
    parser.add_argument('--key', type=lambda x: x.encode(), default=b'',
                        help="Key for AES256CBC encryption")
    parser.add_argument('--iv', type=lambda x: x.encode(), default=b'ZTE%FN$GponNJ025',
                        help="IV for AES256CBC encryption, default: ZTE%FN$GponNJ025")
    parser.add_argument('--signature', type=str, default='',
                        help="Signature in header")
    parser.add_argument("--include-header", action="store_true",
                        help="Include header? (default No)")
    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile
    key = args.key
    iv = args.iv
    signature = args.signature
    include_header = args.include_header

    payload_type = 6
    version = 2
    little_endian_header = True
    chunk_size = 65536
    include_unencrypted_length = False

    data = zcu.compression.compress(infile, chunk_size)

    if payload_type == 6:
        encryptor = CBCXcryptor(chunk_size=chunk_size, include_unencrypted_length=include_unencrypted_length)
        encryptor.set_key(aes_key=key, aes_iv=iv)
        data = encryptor.encrypt(data)
        data.seek(0x04)
        data.write(struct.pack(">1I", 6))
        data.seek(0)

    encoded = zcu.zte.add_header(
        data,
        signature.encode("utf8"),
        version,
        include_header=include_header,
        little_endian=little_endian_header,
    )
    outfile.write(encoded.read())
    print("Done!")


if __name__ == '__main__':
    main()
