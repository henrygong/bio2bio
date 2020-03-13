# How to run postToEth on Windows 10:

## IPFS  
Download IPFS here: https://dist.ipfs.io/#go-ipfs  

Extract go-ipfs_v\<version/>\_windows\_\<32 or 64 bit\>  
Run this on first use: `>path\to\ipfs\ipfs.exe init`  
Run this to start the IPFS daemon: `>path\to\ipfs\ipfs.exe daemon`  

## Python
Download python binary here: https://www.python.org/downloads/windows/  
When installing from the .exe, add python to Path.  

### Packages to install using pip.  
* argparse
* ipfshttpclient
* web3
* hexbytes
* cryptography

### Note that web3 requires C++ to install. Here's how to make that available:

1. Download "Build Tools for Visual Studio 2019" at https://visualstudio.microsoft.com/downloads/
2. Run the executable and select C++ build tools.
3. Restart your computer.
4. In the Windows start menu, search "Visual Studio Installer" and run that.
5. In Installed > Visual Studio Build Tools 2019 > Click Launch.
6. Now you should be able to pip install web3.

## Blockchain account
Guide for getting a blockchain account to post data, using Metamask.  
1. Install Metamask for your browser. Make an account.
2. Follow the instructions here: https://www.rinkeby.io/#faucet to get tokens for use on the Rinkeby testnet.
3. Click the Metamask icon and log in to your account if required.
4. There should be a dropdown menu that says Main Ethereum network. Select Rinkeby Test Network.
5. Click "Account 1" to copy your wallet address. This is used in flag -a for postToEth.py
6. Click the menu icon (hamburger), then Details. Click Export Private Key and enter your account password to get your account private key. Copy this for use with the flag -k for postToEth.py

Now you should be able to run postToEth.py!

`python path\to\postToEth.py <flags>`

## Flags

* -f Path to directory to post to IPFS/blockchain.
* -a Hash for your account.
* -k Private key for your account.
* -e Encrypt the IPFS hash. Default is False.
* -p Previous IPFS hash, if applicable. Default is "".
