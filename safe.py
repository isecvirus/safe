"""
@Author = virus
@Version = 1.0.0

$ Safe is a privacy encryption tool $
"""

import hashlib
import os.path
from util.aes import AES
from argparse import ArgumentParser
from getpass import getpass

parser = ArgumentParser(prog="safe", usage="%(prog)s [options]", description="Safe files using AES-256 encryption.")
parser.add_argument("file", nargs="+", help="File(s) to operate", type=str)
parser.add_argument("-o", "--operate", choices=["encrypt", "decrypt"], required=True, help="Operation type encrypt/decrypt.", type=str)
parser.add_argument("-v", "--verify", action="store_true", required=False, help="Sha256 verify the checksum of the file.")
parser.add_argument("-i", "--iv", required=False, default=("\x00" * 16))
parser.add_argument("-s", "--salt", required=False, default=("\x00" * 18))
args = parser.parse_args()

def get_password():
    password = getpass("Enter passphrase: ")
    repeat = getpass("Re-enter passphrase:  ")

    if repeat == password:
        return password

if len(args.iv) < 16:
    exit("[-] iv must be 16 char long.")
if len(args.salt) < 18:
    exit("[-] salt must be 18 char long.")


try:
    password = get_password()

    if password:
        for file in args.file:
            operate = args.operate
            base_file = os.path.basename(file)

            if os.path.exists(file):
                if os.path.isfile(file):
                    try:
                        aes = AES(password=password, iv=args.iv.encode(), salt=args.salt.encode())
                        if operate == "encrypt":
                            with open(file, "rb+") as efs: # encryption file input stream
                                encrypted_data = aes.encrypt(efs.read())
                                efs.truncate(0) # clear the file content
                                efs.seek(0)  # move to the beginning of the file
                                efs.write(encrypted_data)

                            checksum = f"- sha256({hashlib.sha256(encrypted_data).hexdigest()})" if args.verify else ""
                            print(f"[+] {base_file!r} encrypted {checksum}")
                        elif operate == "decrypt":
                            new_data = None

                            with open(file, "rb+") as dfs: # decryption file stream
                                decrypted_data = aes.decrypt(dfs.read())
                                dfs.truncate(0) # clear the file content
                                dfs.seek(0) # move to the beginning of the file
                                dfs.write(decrypted_data)
                            dfs.close()

                            checksum = f"- sha256({hashlib.sha256(decrypted_data).hexdigest()})" if args.verify else ""
                            print(f"[+] {base_file!r} decrypted {checksum}")
                    except PermissionError:
                        print(f"[-] Access to {base_file!r} isn't permitted!")
                    except ValueError:
                        print(f"[-] Incorrect password!")
                else:
                    print(f"[-] {base_file!r} isn't a file!")
            else:
                print(f"[-] {base_file!r} can't be found!")
    else:
        print(f"[-] Password mismatch!")
except KeyboardInterrupt:
    exit("Interrupted!")