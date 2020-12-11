# bio2bio

## Abstract

Effective data sharing empowers biological research. Here, we present Bio2Bio, a peer-to-peer system for decentralized, secure and version-controlled sharing of biological data. The Bio2Bio system, in theory, is compatible with all existing biological data types, and can be extended to new types as they emerge. Together with downstream analytical pipelines, Bio2Bio creates an extendable ecosystem for collaborative research. We further develop tools for analyzing cellular state correspondence across single cell expression datasets, as an exemplar analytical pipeline in the ecosystem.

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
* pandas

#### Additional packages required to run local web app.
* flask
* json
* contextlib
* flask_wtf
* wtforms


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
app/
&nbsp;&nbsp;app.py - script that operates web app implementation of postToEth.py
&nbsp;&nbsp;templates - html webpages that comprise the app
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
separate capability to send us keys - should not be in the same script as postToEth.py as that asks for very sensitive info (wallet private key).  
password management on the app?  
