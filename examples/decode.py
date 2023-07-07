"""Decode config.bin into config.xml"""
import sys
import argparse
from types import SimpleNamespace
import zcu

from zcu.xcryptors import Xcryptor, CBCXcryptor
from zcu.known_keys import serial_keygen, signature_keygen

def main():
    """the main function"""
    parser = argparse.ArgumentParser(description="Decode config.bin from ZTE Routers",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("infile", type=argparse.FileType("rb"),
                        help="Encoded configuration file e.g. config.bin")
    parser.add_argument("outfile", type=argparse.FileType("wb"),
                        help="Output file e.g. config.xml")
    parser.add_argument("--key", type=lambda x: x.encode(), default=b"",
                        help="Key for AES256CBC decryption")
    parser.add_argument("--iv", type=str, default=b'ZTE%FN$GponNJ025',
                        help="IV for AES256CBC decryption")
    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile


    zcu.zte.read_header(infile, True)
    signature = zcu.zte.read_signature(infile).decode()
    if signature:
        print("Detected signature: %s" % signature)
    payload_type = zcu.zte.read_payload_type(infile)
    print("Detected payload type %d" % payload_type)
    start_pos = infile.tell()

    matched = None
    if payload_type == 6:
        if args.key is None or args.iv is None:
            error("key, iv cannot be null" % len(generated))

        print("key: %s, iv: %s" % (args.key, args.iv))
        decryptor = CBCXcryptor()
        decryptor.set_key(args.key, args.iv)
        infile.seek(start_pos)
        decrypted = decryptor.decrypt(infile)
        if zcu.zte.read_payload_type(decrypted, raise_on_error=False) is not None:
            matched = True
            infile = decrypted

        if matched is None:
            error("Failed to decrypt type 4 payload, tried %d generated key(s)!" % len(generated))
            return 1
    elif payload_type == 0:
        pass
    else:
        error("Unknown payload type %d encountered!" % payload_type)
        return 1

    res, _ = zcu.compression.decompress(infile)
    outfile.write(res.read())

    if matched is not None:
        print("Successfully decoded using %s!" % matched)
    else:
        print("Successfully decoded!")

    return 0


def error(err):
    print(err, file=sys.stderr)


if __name__ == "__main__":
    main()
