#!/bin/bash

# IPFS
ipfsstate=false
if ipfsid=$(docker run --network="host" --detach ipfs/go-ipfs)
    then echo success
    else ipfsstate=true
fi
# Docker of postToEth
docker run -it --user 30109 --network="host" --dns 8.8.8.8 -v ~/posts/postToEth-status:/posts --entrypoint python3 henryzgong/pte-flask /app/postToEth-master/scripts/postToEth.py --query --out /posts/status
# make log
cd ~/posts/postToEth-status/
touch log.txt
now=$(date)
"$now" >> log.txt
# github: postToEth-status
git add .
git commit -m "$now"
git push -u origin main
# kill IPFS if necessary
if [ "$ipfsstate" = false ] ; then
    docker kill "$ipfsid"
fi
