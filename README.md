# BTC_pyrefactor
Coursework of a BTC blockchain system on python


# Feature

- Block
  - BTC structure
  - Coinbase reward Tx
  
- Mining
  - Dynamic nonce difficulty
  - PoW hash reward

- Transaction
  - Change
  - P2PKH Verification

- Storage
  - DiskDB
  - StateDB
  - UTXOpool

- Network
  - Sync
  - Broadcast
  - Consensus
  - Orphan block (FCFS, 51% majority)
 
- User
  - Client Mode
  - Miner Mode


# Env

Python3

Included python lib:
hashlib
pickle
socket
sys
threading
time
json
random
rsa

# Usage

  ```console
# python3 main.py 42001
# python3 main.py 42002
# python3 main.py 42003
  ```

# Refrence

- https://en.bitcoin.it/wiki/Invoice_address

- http://www.righto.com/2014/02/ascii-bernanke-wikileaks-photographs.html#ref7

- https://en.bitcoin.it/wiki/Genesis_block#cite_note-block-1

- https://learnmeabitcoin.com/technical/block-header

- https://www.blockchain.com/btc/tx/ceb1a7fb57ef8b75ac59b56dd859d5cb3ab5c31168aa55eb3819cd5ddbd3d806

- https://bitnodes.io/nodes/?q=Satoshi:0.18.0
