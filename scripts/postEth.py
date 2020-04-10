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

# Versions
# 0.1.0 ability to post to IPFS/Rinkeby test blockchain
# 0.2.0 query posted hashes
# next goal: 0.2.1 get most recent hashes

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
        # https://stackoverflow.com/questions/24919011/
        #   argparse-with-multiple-optional-flags-in-one-dash/24919310

        # Query flags
        self.parser.add_argument('--query', action='store_true', default=False,
                                 help="Run in query mode")
        self.parser.add_argument('--start', type=str,
                                 action='store', default="",
                                 help="Time query start, in YYYYMMDD format")
        self.parser.add_argument('--end', type=str,
                                 action='store', default="",
                                 help="Time query end, in YYYYMMDD format")
        self.parser.add_argument('--unencrypted', action='store_true',
                                 default=False,
                                 help="Query only unencrypted posts")
        self.parser.add_argument('--new', action='store_true',
                                 default=False,
                                 help="Query only most updated posts")
        self.parser.add_argument('--original', action='store_true',
                                 default=False,
                                 help="Query only posts with no valid prevHash")
        self.parser.add_argument('--hash', type=str,
                                 action='store', default="",
                                 help="Query a specific IPFS hash")
        self.parser.add_argument('--depth', type=str,
                                 action='store', default="",
                                 help="Query a specific tree depth")

        # Post flags
        self.parser.add_argument('--post', action='store_true', default=False,
                                 help="Run in post mode")
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
                                 # remove this flag/functionality?
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
                                 version='%(prog)s 0.2.0')
        if inOpts is None:
            self.arguments = vars(self.parser.parse_args())
        else:
            self.arguments = vars(self.parser.parse_args(inOpts))

    def commandInterpreter(self):
        """
        Interpret CommandLine.

        Cleans up CommandLine dict to be discrete variables.
        """
        self.query = self.arguments['query']
        self.start = self.arguments['start']
        self.end = self.arguments['end']
        self.unencrypted = self.arguments['unencrypted']
        self.new = self.arguments['new']
        self.original = self.arguments['original']
        self.hash = self.arguments['hash']
        self.depth = self.arguments['depth']

        self.post = self.arguments['post']
        self.p = self.arguments['previous']
        self.e = self.arguments['doEncrypt']
        self.f = self.arguments['file']
        self.o = self.arguments['folder']
        self.a = self.arguments['account']
        self.k = self.arguments['privateKey']
        self.g = self.arguments['gasPrice']
        self.w = self.arguments['password']

        if self.query:
            import sys
            print("Running in query mode.", file=sys.stderr)
            if self.start != "":
                if self.end == "":
                    toPrint1 = "Query start time is: "
                    from datetime import date
                    endDate = datetime.date.today() + datetime.timedelta(days=1)
                    self.end = endDate.strftime("%Y%m%d")
                    toPrint2 = "; query end time set to today."
                    print(toPrint1, self.start, toPrint2, file=sys.stderr)
                else:
                    toPrint = "Query start/end dates set to:"
                    print(toPrint, self.start, self.end, file=sys.stderr)
            if self.end != "" and self.start == "":
                self.start = "20200101"
                toPrint1 = "Query start time set to 20200101. "
                toPrint2 = "Query end time set to :"
                print(toPrint1, toPrint2, self.end, file=sys.stderr)
            if self.unencrypted:
                print("Filtering query to unencrypted posts.", file=sys.stderr)
            if self.new:
                toPrint = "Filtering query to new/unreferred to posts"
                print(toPrint, file=sys.stderr)


        elif self.post:
            import sys
            print("Running in post mode.", file=sys.stderr)
            if self.e:
                print("Encrypting IPFS hash.", file=sys.stderr)
            if self.e and self.w == "":
                toPrint = "No password supplied, key will be given."
                print(toPrint, file=sys.stderr)
            if self.p == "":
                print("No previous submission hash given.", file=sys.stderr)
            if self.a == "":
                print("No account given. Terminating script.", file=sys.stderr)
                sys.exit()
            if self.k == "":
                toPrint = "No private key given. Terminating script."
                print(toPrint, file=sys.stderr)
                sys.exit()

        else:
            import sys
            print("Neither query mode or post mode selected.", file=sys.stderr)
            sys.exit()

########################################################################
# postToEth
########################################################################


class postToEth(object):
    """
    Post to IPFS/Ethereum blockchain.

    Object that posts input data to IPFS then to blockchain.
    """

    def __init__(self, p, e, f, o, g, w):
        """
        Program initialization.

        Get info from command line.
        Get hash.
        Get encrypted hash if requested.
        Post to blockchain.
        """
        self.previousHash = p
        self.doEncrypt = e
        self.file = f
        self.folder = o
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

    def postEth(self, hash, w3):
        """Post hash to blockchain."""
        # web3 = getWeb3Instance()
        # contract = getWeb3Contract()
        nonce = w3.web3.eth.getTransactionCount(w3.account)
        tx = w3.contract.functions.save(
            hash, self.previousHash)
        tx_dict = tx.buildTransaction({
                    'gas': 400000,  # gas cost ~375k with encrypted IPFS hashes
                    'gasPrice': w3.web3.toWei(self.gasPrice, 'gwei'),
                    'nonce': nonce,
                })
        signed_tx = w3.web3.eth.account.signTransaction(
            tx_dict, private_key=w3.privateKey)
        result = w3.web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        tx_receipt = w3.web3.eth.waitForTransactionReceipt(result)
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


########################################################################
# w3
########################################################################


class w3(object):
    """
    Container for web3 object and contract object.

    Wallet private key is input here.
    """

    def __init__(self, a, k):
        """
        Initialize posted object.

        Needs to be passed web3 object and contract object.
        """
        self.account = a
        self.privateKey = k
        self.getWeb3Instance()
        self.getWeb3Contract()

    def getWeb3Instance(self):
        """Get Web3 instance, using Infura node."""
        from web3 import Web3
        infura_url = \
            "https://rinkeby.infura.io/v3/47f5fd7f17b641ab85073babd72deff3"
        web3 = Web3(Web3.HTTPProvider(infura_url))
        if self.account != "":
            account = self.account
            web3.eth.defaultAccount = account
        else:
            # if account is "" then posting won't work
            pass
        self.web3 = web3

    def getWeb3Contract(self):
        """Get Web3 contract, using address and ABI."""
        address = \
            "0x112cc9bfda373da9e3fd0ddfaecda00bdc7c4a54"
        address = self.web3.toChecksumAddress(address)
        from contract_abi import abi
        contract = self.web3.eth.contract(address=address, abi=abi)
        self.contract = contract


########################################################################
# contractTransactions
########################################################################


class contractTransactions(object):
    """
    Posted hashes on Ethereum blockchain.

    Object that gets and keeps records of hashes, performs transaction queries.
    """

    def __init__(self, w3):
        """
        Initialize posted object.

        Needs to be passed web3 object and contract object.
        """
        self.web3 = w3.web3
        self.contract = w3.contract
        self.getContractTransactionsFromEtherscan()
        self.getPostedHashes()

    def getContractTransactionsFromEtherscan(self):
        """
        Get transactions for our contract from Etherscan API.

        Saves a file to current directory called api.json.
        """
        # for now, we'll use wget but when we move to production use requests
        # this is because requests doesn't work for Rinkeby Etherscan.
        import subprocess # note subprocess.call is used for Python <3.5
        url = ''.join(['http://api-rinkeby.etherscan.io/api?module=account&',
              'action=txlist',
              '&address=0x112cc9bfda373da9e3fd0ddfaecda00bdc7c4a54&',
              '&startblock=0&endblock=99999999&sort=asc&',
              'apikey=3CBBS8DRPJQ8T43EMWHBK4M6C23QMXDX3H'])
              # later, we'll need to have the user input their own API key.
              # it may also behoove us to have an option for where to put
              # the output of the API. It may grow to some tens of MB.
              # then again, it can probably go in memory.
        args = ['wget', '-O', 'api.json', '--header',
                'Accept:application/json', url]
        subprocess.run(args)

    def getPostedHashes(self):
        """Get already posted hashes from api.json."""
        # web3 = self.getWeb3Instance()
        # contract = self.getWeb3Contract()
        # self.getContractTransactionsFromEtherscan()
        import json
        with open('api.json') as f:
            posted = json.load(f)
        if posted['status'] != '1': # successful API call
            # Also, posted['message'] should be 'OK'
            raise SystemExit("Error: API call unsuccessful.")
        txs = []
        for i in range(1, len(posted['result'])):
            # 0th entry is the contract submission
            thisHash = posted['result'][i]['input']
            thisHash = self.contract.decode_function_input(thisHash)
            thisPrevHash = thisHash[1]['_lastHashContent']
            thisHash = thisHash[1]['_hashContent']
            thisTime = posted['result'][i]['timeStamp']

            txs = txs + [[thisHash, thisPrevHash, thisTime]]
        self.txs = txs

    def makeContractTree(self):
        """Make contract tree in igraph format."""
        import igraph
        g = igraph.Graph(directed=True, n=len(self.txs))
        # store tx info per vertex in graph
        g.vs["hash"] = [txData[0] for txData in self.txs]
        g.vs["prevHash"] = [txData[1] for txData in self.txs]
        g.vs["time"] = [txData[2] for txData in self.txs]
        # add edges between vertices and their prevHash
        newEdges = []
        for i, p in enumerate(g.vs["prevHash"]):
            if p != "" and p in g.vs["hash"]:
                edgeFrom = g.vs["hash"].index(p)
                edgeTo = i
                newEdges += [(edgeFrom, edgeTo)]
        g.add_edges(newEdges)
        # find the depth of each vertex in g
        # won't make sense if there are loops in the graph
        gOut = g.get_adjlist(mode="OUT")

        nVertices = len(g.vs)
        vertexDepths = [0] * nVertices
        for vertex in range(nVertices):
            if gOut[vertex] != []:
                for edgeOut in gOut[vertex]:
                    vertexDepths[edgeOut] += (vertexDepths[vertex] + 1)

        g.vs["depth"] = vertexDepths

        self.g = g

    def removeContractVertices(self, toRemove):
        """
        Remove specified vertices from contract tree.

        toRemove: list of booleans, transactions to remove True or False
        """
        self.txs = self.txs[toRemove]

        gIn = self.g.get_adjlist(mode="IN")
        gOut = self.g.get_adjlist(mode="OUT")

        delVertices = []
        for i, removeThis in enumerate(toRemove):
            if removeThis:
                delVertices += [i]

        edgesToAdd = []
        for delVertex in delVertices:
            # IN adjacency of vertex to delete (delVertex)
            delVertexIn = gIn[delVertex]
            # OUT adjacency of delVertex
            delVertexOut = gOut[delVertex]

            # if IN adjacency to delVertex is empty, then
            # we can't make an edge to replace the deleted one
            if delVertexIn != []:
                for outEdge in delVertexOut:
                    newEdge = (delVertexIn[0], outEdge)
                    edgesToAdd = edgesToAdd + [newEdge]

        self.g.add_edges(edgesToAdd)
        self.g.delete_vertices(delVertices)

    def findDuplicate(self, query):
        """Check if user-supplied hash has duplicate hash in posted hashes."""
        if query in [txData[0] for txData in self.txs]:
            return True
        else:
            return False

    def queryTime(self, start, end):
        """
        Query time range.
        Start: YYYYMMDD
        End: YYYYMMDD
        """
        # get UTC timestamps for start and end
        import datetime
        from datetime import timezone
        start = datetime.datetime.strptime(start, "%Y%m%d")
        start = int(start.replace(tzinfo=timezone.utc).timestamp())
        end = datetime.datetime.strptime(end, "%Y%m%d")
        end = int(end.replace(tzinfo=timezone.utc).timestamp())
        # get list of all timeStamps
        times = [txData[2] for txData in self.txs]
        # old filtering method: index range
        # get timepoint after/equal start, before/equal end
        # start = takeAdjacent(times, start, left = False)
        # end = takeAdjacent(times, end, left = True)
        # startIdx = times.index(start)
        # endIdx = times.index(end) + 1 # we want the range inclusive of the end
        # self.txs = self.txs[startIdx:endIdx]
        # current filtering method: list comprehension and method
        isInTimeRange = [time >= start and time <= end for time in times]
        removeContractVertices([not val for val in isInTimeRange])

    def queryHashes(self, query):
        """Query hashes."""
        hashes = [txData[0] for txData in self.txs]
        notQuery = [query != hash for hash in hashes]
        removeContractVertices(notQuery)

    def getMostRecentHashes(self):
        """
        Get most recent hashes.

        Makes tree of lists.
        """
        gOut = self.g.get_adjlist(mode="OUT")
        hasOutEdges = [gOut[i] != [] for i in range(len(gOut))]
        removeContractVertices(hasOutEdges)

    def getUnencryptedHashes(self):
        """
        Get only unencrypted hashes.

        Depends on IPFS address length = 46, so IPNS addresses are incompatible
        Does not otherwise check whether addresses are functional.
        """
        lenIPFSAddress = 46
        hashes = [txData[0] for txData in self.txs]
        isUnencrypted = [len(hash) == lenIPFSAddress for hash in hashes]
        removeContractVertices(isUnencrypted)

    def getOriginalPosts(self):
        """
        Get only posts without previous hashes (that exist in the graph).

        This is not a guarantee that the post is actually original.
        """
        # previous = [txData[1] for txData in self.txs]
        # isOriginal = [prev == "" for prev in previous]
        # self.txs = self.txs[isOriginal]
        getPostsAtDepth(0)

    def getPostsAtDepth(self, depth):
        """
        Get only posts at a certain graph depth.
        """
        removeContractVertices([post != depth for post in g.vs["depth"]])


#################
# helpers
#################

# https://stackoverflow.com/questions/12141150/
#   from-list-of-integers-get-number-closest-to-a-given-value
import bisect

def takeAdjacent(myList, myNumber, left):
    """
    Assumes myList is sorted.
    Returns closest value to myNumber on the left or right.
    """
    if left:
        pos = bisect.bisect_left(myList, myNumber)
    else:
        pos = bisect.bisect_right(myList, myNumber)
    if pos == 0: # first item or less - return first
        return myList[0]
    if pos == len(myList): # last item or more - return last
        return myList[-1]
    before = myList[pos - 1] # previous number
    after = myList[pos] # this number
    if left:
       return before
    else:
       return after


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
    if myCL.post:
        myPost = postToEth(myCL.p, myCL.e, myCL.f, myCL.o,
                           myCL.g, myCL.w)
        hash = myPost.postIPFS()
        # don't need to upload to IPFS everytime for now
        # hash = myCL.f # temporary
        if myPost.doEncrypt:
            hash, key = myPost.encryptHash(hash)
            if myCL.w == "": # if no password given, give the user their key
                print("This is your encryption key, keep it safe: ", key)
            print("Encrypted hash: ", hash)
        else:
            print("IPFS hash: ", hash)
        myw3 = w3(myCL.a, myCL.k)
        myContractTransactions = contractTransactions(myw3)
        if myContractTransactions.findDuplicate(hash):
            # check to make sure the hash hasn't been seen before
            errorMessage = ''.join(["Error: ",
                "This hash has already been submitted to the blockchain."])
            raise SystemExit(errorMessage)
        else: # post to blockchain
            transactionHash = myPost.postEth(hash, myw3)
            print("Transaction hash: ", transactionHash)
    if myCL.query:
        myw3 = w3("", "")
        myContractTxs = contractTransactions(myw3)
        if myCL.unencrypted:
            myContractTxs.getUnencryptedHashes()
        if myCL.new:
            myContractTxs.getMostRecentHashes()
        if myCL.start != "":
            myContractTxs.queryTime(myCL.start, myCL.end)
        if myCL.original:
            myContractTxs.getOriginalPosts()
        if myCL.depth:
            myContractTxs.getPostsAtDepth()
        import json
        with open('filteredTransactions.json', 'w') as f:
            f.write(json.dumps(myContractTxs.txs))
        #TODO: edge cases of unencrypted and new
        #TODO: edge cases of new and date?
        #TODO: write to stdout?


if __name__ == "__main__":
    main()
    raise SystemExit
