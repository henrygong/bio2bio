#!/usr/bin/env python3
"""
IPFS/blockchain interaction app.

Posts data to IPFS
Encrypts resulting hash, if requested
Posts hash to blockchain

https://rinkeby.etherscan.io/address/0x81e75cb1e6c9d49ba9ae244ae5606c95077a7ffc
"""
# hzgong

# Versions
# 0.1.0 ability to post to IPFS/Rinkeby test blockchain
# 0.2.0 query posted hashes
# 0.2.1 igraph tree functionality
# 0.3.0 json metadata from user input, adj matrix printing, tree fixes

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
                                 # TODO: unencrypt with known passwords
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
        self.parser.add_argument('--ext', type=str,
                                 action='store', default="",
                                 help="Get files of a particular extension")
        self.parser.add_argument('--find', type=str,
                                 action='store', default="",
                                 help="Within the query metadata, find text")

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
                                 help="is the data a folder with subfolders?")
                                 # remove this flag/functionality?
                                 # TODO: folder has proper prevhash
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
        self.parser.add_argument('--json', action='store_true', default=False,
                                 help="user walkthrough json for upload")

        # shared flags
        self.parser.add_argument('--version', '-v', action='version',
                                 version='%(prog)s 0.2.1')
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
        self.ext = self.arguments['ext']
        self.find = self.arguments['find']

        self.post = self.arguments['post']
        self.p = self.arguments['previous']
        self.e = self.arguments['doEncrypt']
        self.f = self.arguments['file']
        self.o = self.arguments['folder']
        self.a = self.arguments['account']
        self.k = self.arguments['privateKey']
        self.g = self.arguments['gasPrice']
        self.w = self.arguments['password']
        self.json = self.arguments['json']

        if self.query:
            import sys
            print("Running in query mode.", file=sys.stderr)
            if self.start != "":
                if self.end == "":
                    toPrint1 = "Query start time is: "
                    from datetime import date, timedelta
                    endDate = date.today() + timedelta(days=1)
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
# jsonBuilder
########################################################################


class jsonBuilder(object):
    """Object that builds and saves json metadata file using user inputs."""

    def __init__(self, location):
        """Create json metadata."""
        self.location = location

    def getUserInput(self):
        """Get user input from command line."""
        metaDict = {}
        lastInput = False
        while not lastInput:
            fieldName = input("Field name? ")
            fieldValue = input("{0} value? ".format(fieldName))
            metaDict[fieldName] = fieldValue
            thisLastInput = input("Is this the last field? Y/N (default N)")
            if thisLastInput.upper()=="Y":
                lastInput = True
        self.metaDict = metaDict

    def getCSVInput(self, filename, sep):
        """Get user input from CSV."""
        # TODO: implement this
        pass

    def getGenBankInput(self, filename):
        """Get metadata from genbank formatted text file."""
        metaDict = {}
        with open(filename, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.rstrip()
                # note that colonIndex just finds the first colon
                # this is because colons can be in the field value (e.g. time)
                colonIndex = line.find(':')
                fieldName = line[:colonIndex]
                fieldValue = line[(colonIndex + 1):]
                metaDict[fieldName] = fieldValue
        self.metaDict = metaDict

    def getGenBankInputFolder(self, ext="txt"):
        """Get metadata from genbank formatted text file for subdirectories."""
        import os
        folders = [f.name for f in os.scandir(self.location)]
        original_location = os.getcwd()
        os.chdir(self.location)
        for sub in folders:
            os.chdir(sub)
            files = os.listdir()
            for file in files:
                if file.split('.')[-1] == ext:
                    self.getGenBankInput(file)
                    self.saveJSON(".")
            os.chdir('..')
        os.chdir(original_location)

    def saveJSON(self, location=None):
        """Save json file to location."""
        import os
        import json
        original_location = os.getcwd()
        if location == None:
            os.chdir(self.location)
        else:
            os.chdir(location)
        with open('metadata.json', 'w') as f:
            json.dump(self.metaDict, f)
        os.chdir(original_location)

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
        # if self.folder:
        #     hash = res[-1]['Hash']  # last entry is folder's hash
        # else:
        #     hash = res['Hash']
        # assume f is always a folder
        hash = res[-1]['Hash']  # last entry is folder's hash
        client.close()
        return hash

    def postIPFSFolder(self):
        """Post input data to IPFS."""
        import ipfshttpclient
        client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http')
        # this will fail if the IPFS daemon is not currently running
        res = client.add(self.file)
        # res is a list, whose entries are {'Name':<>, 'Hash':<>, 'Size':<>}
        if self.folder:
            # hash = res[-1]['Hash']  # last entry is folder's hash

            # notes on doing subfolders
            # if you use a VPN or firewall it may rate limit or block the high
            # volume of requests
            # ipfshttpclient.exceptions.ErrorResponse.args[0] is
            #   'this dag node is a directory'
            #   when you try to cat the hash
            folders = []
            # resCounter = -1
            for sub in res:
            	# resCounter += 1
            	#if resCounter%250 == 0:
            		#time.sleep(30)
                theseLinks = client.object.links(sub['Hash'])
                if 'Links' in theseLinks:
                    folders.append(sub)
            topFolder = folders.pop()
            hash = topFolder['Hash']
        else:
            hash = res['Hash']
            folders = []
        client.close()
        return hash, folders

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
            "0x81e75cb1e6c9d49ba9ae244ae5606c95077a7ffc"
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
        self.makeContractTree()

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
              '&address=0x81e75cb1e6c9d49ba9ae244ae5606c95077a7ffc&',
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
        self.gOut = g.get_adjlist(mode="OUT")
        self.gIn = g.get_adjlist(mode="IN")

        nVertices = len(g.vs)
        vertexDepths = [0] * nVertices
        for vertex in range(nVertices):
            if self.gOut[vertex] != []:
                for edgeOut in self.gOut[vertex]:
                    vertexDepths[edgeOut] += (vertexDepths[vertex] + 1)

        g.vs["depth"] = vertexDepths

        self.g = g

    def removeContractVertices(self, toRemove):
        """
        Remove specified vertices from contract tree.

        toRemove: list of booleans, transactions to remove True or False
        """
        self.txs = [value for index, value in enumerate(self.txs) \
                    if toRemove[index] == False]
        delVertices = []
        for i, removeThis in enumerate(toRemove):
            if removeThis:
                delVertices += [i]
        edgesToAdd = []
        for delVertex in delVertices:
            # IN adjacency of vertex to delete (delVertex)
            delVertexIn = self.gIn[delVertex]
            # OUT adjacency of delVertex
            delVertexOut = self.gOut[delVertex]

            # if IN adjacency to delVertex is empty, then
            # we can't make an edge to replace the deleted one
            if delVertexIn != []:
                for outEdge in delVertexOut:
                    newEdge = (delVertexIn[0], outEdge)
                    edgesToAdd = edgesToAdd + [newEdge]

        self.g.add_edges(edgesToAdd)
        self.g.delete_vertices(delVertices)
        self.gOut = self.g.get_adjlist(mode="OUT")
        self.gIn = self.g.get_adjlist(mode="IN")

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
        times = [int(txData[2]) for txData in self.txs]
        # old filtering method: index range
        # get timepoint after/equal start, before/equal end
        # start = takeAdjacent(times, start, left = False)
        # end = takeAdjacent(times, end, left = True)
        # startIdx = times.index(start)
        # endIdx = times.index(end) + 1 # we want the range inclusive of the end
        # self.txs = self.txs[startIdx:endIdx]
        # current filtering method: list comprehension and method
        isInTimeRange = [time >= start and time <= end for time in times]
        self.removeContractVertices([not val for val in isInTimeRange])

    def queryHashes(self, query):
        """Query hashes."""
        hashes = [txData[0] for txData in self.txs]
        notQuery = [query != hash for hash in hashes]
        self.removeContractVertices(notQuery)

    def getMostRecentHashes(self):
        """
        Get most recent hashes.

        Makes tree of lists.
        """
        hasOutEdges = [self.gOut[i] != [] for i in range(len(self.gOut))]
        self.removeContractVertices(hasOutEdges)

    def getUnencryptedHashes(self):
        """
        Get only unencrypted hashes.

        Depends on IPFS address length = 46, so IPNS addresses are incompatible
        Does not otherwise check whether addresses are functional.
        """
        lenIPFSAddress = 46
        hashes = [txData[0] for txData in self.txs]
        isEncrypted = [len(hash) != lenIPFSAddress for hash in hashes]
        encryptedHashes = [hash for hash in hashes if len(hash) != lenIPFSAddress]
        self.removeContractVertices(isEncrypted)

    def getOriginalPosts(self):
        """
        Get only posts without previous hashes (that exist in the graph).

        This is not a guarantee that the post is actually original.
        """
        # previous = [txData[1] for txData in self.txs]
        # isOriginal = [prev == "" for prev in previous]
        # self.txs = self.txs[isOriginal]
        self.getPostsAtDepth(0)

    def getPostsAtDepth(self, depth):
        """
        Get only posts at a certain graph depth.
        """
        self.removeContractVertices([post != depth for post in self.g.vs["depth"]])

    def getNodeOfHash(self, query):
        """Get igraph graph node of query hash."""
        return self.g.vs["hash"].index(query)

    def getRoot(self, query):
        """Get root of this node in the tree."""
        noIn = False
        while not noIn:
            if self.gIn[query] == []:
                noIn = True
            else:
                query = self.gIn[query][0]
        return query

    def getTree(self, root):
        """Get tree nodes associated with this node."""
        # if list treeNodes doesn't exist, make it
        if not hasattr(self, 'treeNodes'):
            self.treeNodes = []
            self.treeNodes.append(root)
        # recursively get tree nodes starting with root
        for node in self.gOut[root]:
            self.treeNodes.append(node)
            self.getTree(root=node)

    def getSubGraphAdjacency(self, root=None):
        """
        Get adjacency matrix for subgraph of self.g from self.treeNodes.

        Requires getTree() to have been run or a root to be given.
        If a root is given then getTree(root) will be run to get self.treeNodes.
        """
        if not hasattr(self, 'treeNodes') and root != None:
            self.getTree(root)
        return self.g.induced_subgraph(self.treeNodes).get_adjacency()

    def printTree(self, root, query=None, printRoot=True):
        """Print tree associated with this root."""
        # if this is the root print it
        if printRoot == True:
            print("Printing tree associated with query.",
                  "Query is <q>. Encrypted is <e>.",
                  "3 dots for each level of depth from original post.")
            dots = "..."*self.g.vs["depth"][root]
            thisRootHash = str(self.g.vs["hash"][root])
            # <e> if this is encrypted
            if len(thisRootHash) != 46:
                thisRootHash = "<e>" + thisRootHash
            # <q> if it's the query
            if root == query:
                print(dots + "<q>" + thisRootHash)
            else:
                print(dots + thisRootHash)
        # recursively print tree starting with root's out nodes
        for node in self.gOut[root]:
            dots = "..."*self.g.vs["depth"][node]
            thisNodeHash = str(self.g.vs["hash"][node])
            # <e> if this is encrypted
            if len(thisNodeHash) != 46:
                thisNodeHash = "<e>" + thisNodeHash
            # <q> if it's the query
            if node == query:
                print(dots + "<q>" + thisNodeHash)
            else:
                print(dots + thisNodeHash)
            self.printTree(root=node, query=query, printRoot=False)

    def treeNodesToMetadataQuery(self, treeNodes=None):
        """Convert treeNodes list (index of tree nodes) to hash list"""
        theseTreeNodes = self.treeNodes
        if treeNodes != None:
            theseTreeNodes = treeNodes
        return [self.g.vs['hash'][node] for node in theseTreeNodes]

    def getMetadata(self, query, ext, dir):
        """
        Get metadata for query.

        Assumes query is list of hashes.
        Assumes metadata is in files with extension stored in ext, one/folder.
        """
        import os
        newDir = "queryMetadataInExt_{0}".format(ext)
        os.chdir(dir)
        import ipfshttpclient
        client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001/http')
        for hash in query:
            theseLinks = client.object.links(hash)
            if 'Links' in theseLinks:
                for link in theseLinks['Links']:
                    thisName = link['Name']
                    # split thisName by . then last item in list should be ext
                    thisExt = thisName.split('.')[-1]
                    if thisExt == ext:
                        client.get(link['Hash'])
                        # print(link)
        client.close()
        os.chdir('..')

    def collateJSONMetadata(self, dir):
        """
        Collate metadata if in JSON format. Assumes getMetadata has been run.
        """
        import os
        import json
        os.chdir(dir)
        metadata = []
        for file in os.listdir():
            # print(file)
            try:
                with open(file) as f:
                    metadata.append(json.load(f))
            except:
                print("could not decode this JSON")
        os.chdir('..')
        return metadata

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
    if myCommandLine == None:
        myCL = CommandLine()
    else:
        myCL = myCommandLine
    myCL.commandInterpreter()
    if myCL.post:
        myPost = postToEth(myCL.p, myCL.e, myCL.f, myCL.o,
                           myCL.g, myCL.w)
        if myCL.o:
            hash, folders = myPost.postIPFSFolder()
            # TODO: JSON
        else:
            if myCL.json:
                myJSONBuilder = jsonBuilder(myCL.f)
                myJSONBuilder.getUserInput()
                myJSONBuilder.saveJSON()
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
            if myCL.o:
                #TODO: encryption for multiple subfolders
                #TODO: check whether subfolders have been posted
                transactionHash = myPost.postEth(hash, myw3)
                myPost.PreviousHash = hash
                for folder in folders:
                    myPost.postEth(folder['Hash'], myw3)
            else:
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
        if myCL.hash:
            try:
                queryNode = myContractTxs.getNodeOfHash(myCL.hash)
                queryRoot = myContractTxs.getRoot(queryNode)
                myContractTxs.getTree(queryRoot)
                myContractTxs.printTree(root=queryRoot, query=queryNode)
                print("") # add a newline after tree
                queryAdj = list(myContractTxs.getSubGraphAdjacency())
                # import csv
                adjName = "adj_" + myCL.hash + ".csv"
                print("Writing " + adjName + " with tree adjacency matrix.")
                # with open(adjName, 'w') as f:
                    # csv.writer(f).writerows(queryAdj)
                import pandas as pd
                dfAdj = pd.DataFrame(queryAdj)

                labels = [myContractTxs.g.vs['hash'][node] \
                          for node in myContractTxs.treeNodes]
                dfAdj.index = labels # hash of node in adj matrix
                # dfAdj.columns = myContractTxs.treeNodes
                dfAdj.to_csv(adjName)
                if myCL.ext:
                    if myContractTxs.treeNodes == []:
                        myContractTxs.treeNodes = [queryNode]
                    myQuery = myContractTxs.treeNodesToMetadataQuery()
                    # myQuery = ["QmRxyM8faGbo653eFNAUbE6duEAZSr795aEM9dC4yaGyqT"]
                    import os
                    newDir = "queryMetadataInExt_" + myCL.ext + "_" + myCL.hash
                    dirNotMade = True
                    while dirNotMade:
                        try:
                            os.mkdir(newDir)
                            dirNotMade = False
                        except FileExistsError as e:
                            newDir = newDir + "1"
                    myContractTxs.getMetadata(myQuery, myCL.ext, newDir)
                    if myCL.ext == "json":
                        myMeta = myContractTxs.collateJSONMetadata(newDir)
                        # import pandas as pd
                        dfMeta = pd.DataFrame(myMeta)
                        dfMeta.index = myQuery
                        if myCL.find:
                            findInRow = []
                            for i in range(len(dfMeta.index)):
                                findInRow.append(
                                    sum(dfMeta.iloc[i].str.contains(myCL.find))
                                )
                            dfMeta["find"] = findInRow
                        dfName = "collatedJSONMetadata_" + myCL.hash + ".csv"
                        print("Collating jsons to " + dfName)
                        dfMeta.to_csv(dfName)
                else:
                    myQuery = myContractTxs.treeNodesToMetadataQuery()
                    # myContractTxs.getMetadata(myQuery, "txt")
            except ValueError:
                print("Hash not found with the given filters.")



        import json
        with open('filteredTransactions.json', 'w') as f:
            f.write(json.dumps(myContractTxs.txs))
        #TODO: edge cases of unencrypted and new
        #TODO: edge cases of new and date?
        #TODO: write to stdout?


if __name__ == "__main__":
    main()
    raise SystemExit
