#!/usr/bin/env bash
set -e

make start
sleep 2

python authority_client.py setup --node http://127.0.0.1:8001
sleep 2

python authority_client.py open  --node http://127.0.0.1:8001
sleep 2

python voter_client.py --voter-id alice --candidate 0
sleep 1
python voter_client.py --voter-id bob   --candidate 1
sleep 1
python voter_client.py --voter-id carol --candidate 0
sleep 1
python voter_client.py --voter-id dave  --candidate 0
sleep 1
python voter_client.py --voter-id eve   --candidate 1
sleep 1

python authority_client.py close   --node http://127.0.0.1:8001
sleep 1

python authority_client.py decrypt --authority node1
sleep 3

python authority_client.py decrypt --authority node2
sleep 3

python authority_client.py tally   --node http://127.0.0.1:8001
sleep 3
python authority_client.py tally   --node http://127.0.0.1:8001
sleep 3

make stop && make clean