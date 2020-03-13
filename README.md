# postToEth

## Abstract

"Creating a data sharing platform on a blockchain allows standard algorithms to take care of data synchronization, authentication, privacy, and validation. IPFS, or Interplanetary File System, is the peer-to-peer distributed file system in which users store data.  Data are indexed using a cryptographic hash, which is a one-way function that creates a small string based on the data that can be used as a link that allows users to access the data directly from a peer that has a local instance of the data. The hash function produces drastically different, unique results even for only slightly different data. The hashes, and transactions using them, are stored on the Ethereum blockchain. A blockchain is a ledger maintained by a peer-to-peer network. Each peer keeps a copy of the network. The network is made up of a series or chain of blocks, which each store transaction data. The Ethereum blockchain further has the capability to run smart contracts, which are Turing-complete scripts that can store variables and run functions. All peers will calculate the function calls of a smart contract, and the results and variables are stored in the blockchain. This provides verification on a massive scale. Using one of these smart contracts, we store IPFS hashes of our data, and hashes of data changes and transactions, on the blockchain, providing a public, distributed index of the data with a verifiable history. Blockchain technology can provide a revolutionary mechanism for science to share results because it does not rely on an expensive and slow central trusted authority to harvest boutique datasets and serve them out to qualified members of the research community. " - Research Strategy-CEGS Research Project (proposal).

![Overview](overview.png)

## Installation
This is an installation guide for macOS and Linux. For Windows, go to [Windows install guide](windows-install.md).

### IPFS  
Follow the instructions to install IPFS here: https://docs.ipfs.io/guides/guides/install/#installing-from-a-prebuilt-package

Run this on first use: `$ipfs init`  
Run this to start the IPFS daemon: `$ipfs daemon`  

### Packages to install using python pip.  
* argparse
* ipfshttpclient
* web3 (You may need to update your cython to install its dependencies.)
* hexbytes
* cryptography

### Blockchain account
Guide for getting a blockchain account to post data, using Metamask.  
1. Install Metamask for your browser. Make an account.
2. Follow the instructions here: https://www.rinkeby.io/#faucet to get tokens for use on the Rinkeby testnet.
3. Click the Metamask icon and log in to your account if required.
4. There should be a dropdown menu that says Main Ethereum network. Select Rinkeby Test Network.
5. Click "Account 1" to copy your wallet address. This is used in flag -a for postToEth.py
6. Click the menu icon (hamburger), then Details. Click Export Private Key and enter your account password to get your account private key. Copy this for use with the flag -k for postToEth.py

Now you should be able to run postToEth.py!

`python path\to\postToEth.py <flags>`

### Flags

* -f Path to directory to post to IPFS/blockchain.
* -a Hash for your account.
* -k Private key for your account.
* -e Encrypt the IPFS hash. Default is False.
* -p Previous IPFS hash, if applicable. Default is "".


## Major repository components:

contracts/  
&nbsp;&nbsp;HashStore.sol - solidity smart contract that stores information on the blockchain  
&nbsp;&nbsp;&nbsp;&nbsp;Inputs: hash (text), tag, previous hash if given  
scripts/  
&nbsp;&nbsp;postToEth.py - script that posts data to IPFS/blockchain  
public/  
&nbsp;&nbsp;index.html - Dapp that allows users to view files posted through this program, maintains an index of files  

Pseudocode for uploader:  

postToIPFSBlockchain(data, dataTypeTag, previousVersionHash, doEncrypt){  
&nbsp;&nbsp;&nbsp;&nbsp;key = NULL  
&nbsp;&nbsp;&nbsp;&nbsp;IPFSIndex = getIPFSIndex()  
&nbsp;&nbsp;&nbsp;&nbsp;hash = getIPFSHash(data)  
&nbsp;&nbsp;&nbsp;&nbsp;if hash in IPFSIndex:  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return ("hash found in IPFS index, this data is already posted")  
&nbsp;&nbsp;&nbsp;&nbsp;if doEncrypt:  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;hash, key = encrypt(hash)  
&nbsp;&nbsp;&nbsp;&nbsp;transactionID = postToBlockchain(hash, dataTypeTag, previousVersionHash)  
&nbsp;&nbsp;&nbsp;&nbsp;return (hash, key, transactionID)  
}  
 
A Docker image file will be made available with dependencies installed.

Dependencies of postToEth.py:  
argparse  
ipfshttpclient  
web3  
hexbytes  
cryptography  

Also, an IPFS daemon must be running in the background at port 5001.

Check out your data at these IPFS mirrors:  
ipfs.io\/ipfs\/\<Your hash here\>  
cloudflare-ipfs.com\/ipfs\/\<Your hash here\>  

View your transaction here:
rinkeby.etherscan.io

Pictures of the process:

Running the IPFS daemon:  
![IPFS-Daemon](ipfs_daemon.PNG)  
  
Running postToEth.py:  
![postToEth](postToEth.png)  
  
Viewing the transaction on etherscan.io:  
![viewTransaction](viewTx.PNG)  

TODO:  
use passwords instead of generated keys? Has pros/cons  
check whether the hash has been uploaded already  
separate capability to send us keys - should not be in the same script as postToEth.py as that asks for very sensitive info (wallet private key).  
remove tags
webpage version for user accessibility  
