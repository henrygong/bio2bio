#!/usr/bin/env python3
"""
IPFS/blockchain interaction app.

Posts data to IPFS
Encrypts resulting hash, if requested
Posts hash to blockchain

TODO
check hash versus known hashes
https://rinkeby.etherscan.io/address/0xe9e6295ecb5016b9a3474e85e9ac2d10108df4ec
"""
# hzgong

########################################################################
# CommandLine
########################################################################


class CommandLine(object):
    """
    Handle the command line, usage, and help requests.

    Attributes
    ----------
    myCommandLine.args is a dict of arguments

    Methods
    -------
    __init__: initialization
    commandInterpreter(): make command line stuff more discrete

    """

    def __init__(self, inOpts=None):
        """
        Command line constructor.

        Parse command line using argparse.
        """
        import argparse
        self.parser = argparse.ArgumentParser(
            description="upload data to IPFS/blockchain",
            epilog="submit data to IPFS and store a record on blockchain",
            add_help=True,
            prefix_chars='-',
            usage='%(prog)s [options]'
        )
        # https://stackoverflow.com/questions/24919011/argparse-with-multiple-optional-flags-in-one-dash/24919310
        self.parser.add_argument('--type', '-t', type=str,
                                 action='store', default="",
                                 help="Data type")
        self.parser.add_argument('--previous', '-p', type=str,
                                 action='store', default="",
                                 help="Previous submission hash")
        self.parser.add_argument('--doEncrypt', '-e', action='store_true',
                                 default=False,
                                 help="Encrypt the data?")
        self.parser.add_argument('--file', '-f', type=str,
                                 action='store', default=".",
                                 help="location of data to upload")
        self.parser.add_argument('--folder', '-o', action='store_true',
                                 default=True,
                                 help="is the data a folder?")
        self.parser.add_argument('--account', '-a', type=str,
                                 action='store', default="",
                                 help="wallet hash")
        self.parser.add_argument('--privateKey', '-k', type=str,
                                 action='store', default="",
                                 help="wallet private key")
        self.parser.add_argument('--gasPrice', '-g', type=str,
                                 action='store', default="40",
                                 help="transaction gas price in gWei")
        self.parser.add_argument('--password', '-w', type=str,
                                 action='store', default="",
                                 help="user supplied password")
        self.parser.add_argument('--version', '-v', action='version',
                                 version='%(prog)s 0.1.0')
        if inOpts is None:
            self.arguments = vars(self.parser.parse_args())
        else:
            self.arguments = vars(self.parser.parse_args(inOpts))

    def commandInterpreter(self):
        """
        Interpret CommandLine.

        Cleans up CommandLine dict to be discrete variables.
        Also tells the user that the program is falling back to no -t if
        -t is specified with no -a.
        """
        self.t = self.arguments['type']
        self.p = self.arguments['previous']
        self.e = self.arguments['doEncrypt']
        self.f = self.arguments['file']
        self.o = self.arguments['folder']
        self.a = self.arguments['account']
        self.k = self.arguments['privateKey']
        self.g = self.arguments['gasPrice']
        self.w = self.arguments['password']
        if self.e:
            import sys
            print("Encrypting IPFS hash.", file=sys.stderr)
        if self.e and self.w == "":
            print("No password supplied, key will be given.", file=sys.stderr)
        if self.p == "":
            import sys
            print("No previous submission hash given.", file=sys.stderr)
        if self.a == "":
            import sys
            print("No account given. Terminating script.", file=sys.stderr)
            sys.exit()
        if self.k == "":
            import sys
            print("No private key given. Terminating script.", file=sys.stderr)
            sys.exit()

########################################################################
# postToEth
########################################################################


class postToEth(object):
    """
    Post to IPFS/Ethereum blockchain.

    Object that posts input data to IPFS then to blockchain.
    """

    def __init__(self, t, p, e, f, o, a, k, g, w):
        """
        Program initialization.

        Get info from command line.
        Get hash.
        Get encrypted hash if requested.
        Post to blockchain.
        """
        self.dataType = t
        self.previousHash = p
        self.doEncrypt = e
        self.file = f
        self.folder = o
        self.account = a
        self.privateKey = k
        self.gasPrice = g
        self.password = w

    def postIPFS(self):
        """Post input data to IPFS."""
        import ipfshttpclient
        client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http')
        # this will fail if the IPFS daemon is not currently running
        res = client.add(self.file)
        # res is a list, whose entries are {'Name':<>, 'Hash':<>, 'Size':<>}
        if self.folder:
            hash = res[-1]['Hash']  # last entry is folder's hash
        else:
            hash = res['Hash']
        return hash

    def postEth(self, hash):
        """Post hash to blockchain."""
        from web3 import Web3

        infura_url = \
            "https://rinkeby.infura.io/v3/47f5fd7f17b641ab85073babd72deff3"
        web3 = Web3(Web3.HTTPProvider(infura_url))
        account = self.account
        web3.eth.defaultAccount = account
        address = \
            "0xe9e6295ecb5016b9a3474e85e9ac2d10108df4ec"
        address = web3.toChecksumAddress(address)
        from contract_abi import abi
        contract = web3.eth.contract(address=address, abi=abi)
        # tx = contract.functions.save(hash, self.dataType, self.previousHash)
        # tx.call()
        nonce = web3.eth.getTransactionCount(account)
        tx = contract.functions.save(
            hash, int(self.dataType), self.previousHash)
        tx_dict = tx.buildTransaction({
                    'gas': 400000,  # gas cost ~375k with encrypted IPFS hashes
                    'gasPrice': web3.toWei(self.gasPrice, 'gwei'),
                    'nonce': nonce,
                })
        signed_tx = web3.eth.account.signTransaction(
            tx_dict, private_key=self.privateKey)
        result = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        tx_receipt = web3.eth.waitForTransactionReceipt(result)
        import hexbytes
        # default output is HexBytes(address) which outputs bytes.
        if tx_receipt['status'] != 1:
            return 'failed transaction'
        else:
            return hexbytes.HexBytes(tx_receipt['transactionHash']).hex()

    def encryptHash(self, hash):
        """Encrypt hash."""
        # https://cryptography.io/en/latest/fernet/
        from cryptography.fernet import Fernet
        print("IPFS hash: ", hash)
        if self.password == "":
            # no password was input. Generate a key.
            key = Fernet.generate_key()
            f = Fernet(key)
            token = f.encrypt(hash.encode('utf-8'))
        else:
            # password was input. Use that in key.
            import os
            import base64
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.backends import default_backend
            backend = default_backend()
            # salt = os.urandom(16)
            salt = os.urandom(0) # Nowhere to store salts so we'll use no salt
            # derive
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=backend
             )
            # key = kdf.derive(self.password.encode('utf-8'))
            passwordBytes = self.password.encode('utf-8')
            key = base64.urlsafe_b64encode(kdf.derive(passwordBytes))
            f = Fernet(key)
            token = f.encrypt(hash.encode('utf-8'))
        return token, key

#################
# main
#################


def main(myCommandLine=None):
    """
    Main.

    Implement the program by getting info from the command line then
    running postToEth functionality.
    """
    myCL = CommandLine()
    myCL.commandInterpreter()
    myPost = postToEth(myCL.t, myCL.p, myCL.e, myCL.f, myCL.o,
                       myCL.a, myCL.k, myCL.g, myCL.w)
    # hash = myPost.postIPFS()
    hash = myCL.f
    if myPost.doEncrypt:
        hash, key = myPost.encryptHash(hash)
        if myCL.w == "":
            print("Encryption key - keep this safe: ", key)
        print("Encrypted hash: ", hash)
    else:
        print("IPFS hash: ", hash)
    transactionHash = myPost.postEth(hash)
    print("Transaction hash: ", transactionHash)


if __name__ == "__main__":
    main()
    raise SystemExit
