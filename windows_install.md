# How to run postToEth on Windows 10:

## IPFS  
Download IPFS here: https://dist.ipfs.io/#go-ipfs  

Run this on first use: `>\path\to\ipfs\ipfs.exe init`  
Run this to start the IPFS daemon: `>\path\to\ipfs\ipfs.exe daemon`  

## Python
Download python here: https://www.python.org/downloads/windows/

Packages to install using pip.
* argparse
* ipfshttpclient
* web3
* hexbytes
* cryptography

### Note that web3 requires C++ to run.

1. Download "Build Tools for Visual Studio 2019" at https://visualstudio.microsoft.com/downloads/
2. Run the executable and select C++ build tools.
3. Restart your computer.
4. In the Windows start menu, search "Visual Studio Installer" and run that.
5. Click Launch.
6. Now you should be able to pip install web3.

Now you should be able to run postToEth.py
