import hashlib
import pickle
import socket
import sys
import threading
import time
import json
import random
#import base58
#from datetime import datetime
import rsa
#import pymongo

class Block:
    def __init__(self, nextIndex, nextBlockHash, previousBlockhash, nextTimestamp, Txroot_hash, blockData, nonce, difficulty):
      
        self.index = nextIndex
        ##load the latest full blockchain to get heightlevel
        self.timestamp = nextTimestamp
        self.hash = nextBlockHash
        self.previousHash = previousBlockhash
        self.difficulty = difficulty
        self.nonce = nonce
        self.merkleroot = Txroot_hash#roothash

        self.data = blockData#transactions record


    def get_blockHeader(): #replace
        return 0



class Transaction:
    def __init__(self, id, txIds, receivers, amount, fee, message):
        #called by create_newTransaction & read_oldTransaction

        #recalculate the txId for create and read tx
        self.id = id#self.get_TransactionHash()

        #init unspent txid & Index
        self.txIns = []
        for Initem in txIds:
          #print (Initem)
          self.temp = TxIn(Initem[0],Initem[1])
          self.txIns.append(self.temp)
        
        #init receiver address & amount
        self.txOuts = []  
        for Outitem in receivers:
          #print (Outitem)
          self.temp = TxOut(Outitem[0],Outitem[1])
          self.txOuts.append(self.temp)

        self.amount = amount
        self.fee = fee
        self.message = message



    def update_TransactionSignature(self, sig, pubKey):
        for Initem in self.txIns:
          Initem.signature = [sig , pubKey]


class TxIn:
    def __init__(self, txId, txIndex):
        self.txOutId = txId #previous txId 
        self.txOutIndex = '0' #locate the UTXO address(unspent)
        self.signature = '' #sig + pubKey

class TxOut:
    def __init__(self, address, amount):
        self.address = address
        self.amount = amount



class BlockChain:
  def __init__(self):
    self.storage = Storage()
    self.minerAddress ='' #init after blockchain obj created
    self.difficulty = 16
    self.latest_adustedDifficulty =[] #
    self.coinBaseAmount = 50
    self.BLOCK_GENERATION_INTERVAL = 10
    self.DIFFICULTY_ADJUSTMENT_INTERVAL =10
    #self.latestBlockChainHeight = ''#init by 

  def adjust_difficulty(self, newBlock):
      newBlockIndex = int(newBlock.index)
      if (newBlockIndex % self.DIFFICULTY_ADJUSTMENT_INTERVAL == 0) and (newBlockIndex != 0):
        rawBlockChain = self.storage.read_diskDB_rawBlockChain()
        prevAdjustedBlock = rawBlockChain[newBlockIndex -self.DIFFICULTY_ADJUSTMENT_INTERVAL]
        expected_time = self.BLOCK_GENERATION_INTERVAL * self.DIFFICULTY_ADJUSTMENT_INTERVAL
        taken_time = newBlock.timestamp - prevAdjustedBlock.timestamp

        print("************")
        if (taken_time < expected_time / 2):
          self.difficulty= prevAdjustedBlock.difficulty +1
          print ("\nDifficulty adjustment: taken_time < expected_time / 2 => difficulty +1\n")
        elif(taken_time > expected_time * 2):
          self.difficulty= prevAdjustedBlock.difficulty -1
          print ("\nDifficulty adjustment: taken_time > expected_time * 2 => difficulty -1\n")
        else:
          print ("Difficulty adjustment: taken_time ~ expected_time  => difficulty remains unchange\n")
        print("************")

  #when the rawblockchain loaded from disk, update difficulty
  def update_difficulty(self):
      latestblock = self.get_latestBlock()
      self.difficulty = int(latestblock.difficulty)

  def get_merkleRoot(self, Tx_shortlist):
      rootTxhash = ''

      for Txitem in Tx_shortlist:
        rootTxhash = rootTxhash + Txitem.id

      s = hashlib.sha256()
      s.update((rootTxhash).encode("utf-8"))
      rootTxhash = s.hexdigest()
      return rootTxhash

  def get_newBlockHash(self, index, previousHash, timestamp, Txroot_hash, nonce, difficulty):
        s = hashlib.sha256()
        s.update(
            (
                str(index)
                + previousHash
                + str(timestamp)
                + Txroot_hash
                + str(nonce)
                + str(difficulty)
            ).encode("utf-8")
        )
        h = s.hexdigest()
        return h

  def generate_genesisBlock(self):
      Index = 0
      previousBlockHash ='Hello World!'
      Timestamp = int(time.time())

      coinbBaseTx = self.create_coinbBaseTransaction(0)#fee =0
      Tx_shortlist = []
      Tx_shortlist.append(coinbBaseTx)

      Txroot_hash = self.get_merkleRoot(Tx_shortlist)
      blockData = Tx_shortlist
      nonce = 0
      difficulty = self.difficulty

      #mine the valid block for  matching the nextHash and difficulty 
      isNextHashNonceFound = False
      nextHash =''      
      while (isNextHashNonceFound == False):
        nextHash = self.get_newBlockHash(Index, previousBlockHash, Timestamp, Txroot_hash, nonce, difficulty)

        dec = int(nextHash , 16)
        bin256 = bin(dec)[2:].zfill(256)

        if (int(bin256[:difficulty]) == 0):
          isNextHashNonceFound = True
        else:
          nonce = nonce+1

      #create the Blcok object for genesisBlock + write_diskDB
      genesisBlock = Block(Index, nextHash, previousBlockHash, Timestamp, Txroot_hash, blockData, nonce, difficulty)
      self.storage.write_diskDB_rawBlockChain(genesisBlock)
      #return genesisBlock

  def get_latestBlock(self):

      #read from storage
      rawBlockChainArr = self.storage.read_diskDB_rawBlockChain()
      #get last heightlevel
      currentHeightLevel = len(rawBlockChainArr) 

      #currentHeightLevel must > 0
      latestBlock = rawBlockChainArr[currentHeightLevel-1]



      #create the Blcok object for LatestBlock
      #LatestBlock = Block(index, hash, previousBlockHash, Timestamp, Txroot_hash, blockData, nonce, difficulty)

      return latestBlock

  #function called by Miner to mine a new Block
  def generate_NextBlock(self, coinbBaseTx, Tx_shortlist):
      previousBlock = self.get_latestBlock()

      previousBlockHash = previousBlock.hash
      nextIndex = previousBlock.index + 1
      nextTimestamp = int(time.time())
      nonce = 0
      difficulty = self.difficulty

      Tx_shortlist.insert(0, coinbBaseTx)
      Txroot_hash = self.get_merkleRoot(Tx_shortlist)

      blockData =Tx_shortlist#coinbaseTx + clientTx
      print(blockData)

      print("\nStart mining the new Block...\n")
      #mine the valid block for  matching the nextHash and difficulty 
      isNextHashNonceFound = False
      nextHash =''      
      while (isNextHashNonceFound == False):
        nextHash = self.get_newBlockHash(nextIndex, previousBlockHash, nextTimestamp, Txroot_hash, nonce, difficulty)

        dec = int(nextHash , 16)
        bin256 = bin(dec)[2:].zfill(256)

        if (int(bin256[:difficulty]) == 0):          
          isNextHashNonceFound = True
          print('binary format of NextBlcokHash:'+ bin256 )
          print('the leading bits:'+ bin256[:difficulty] )
          print( 'is enough leading zero bits found? (difficulty =' +str(difficulty) + '):'+ str(int(bin256[:difficulty]) == 0))
          print('nonce:'+str(nonce))
        else:
          nonce = nonce+1




      #verify the block nonce, size, 


      #create the valid Block
      newBlock = Block(nextIndex, nextHash, previousBlockHash, nextTimestamp, Txroot_hash, blockData, nonce, difficulty)
      self.storage.write_diskDB_rawBlockChain(newBlock)
      return newBlock

##End of block function


  def get_TransactionString(self, txIns, txOuts):
#loop through all the input and output arr, concact all data
#test: txIns, txOuts has multi input, 2 output
#call by create_newTransaction & read_oldTransaction

        txInContent = ''
        for Initem in txIns:
          txInContent = txInContent + str(Initem[0]) + str(Initem[1])

        txOutContent = ''
        for Outitem in txOuts:        
           txOutContent = txOutContent + str(Outitem[0]) + str(Outitem[1])

        print("NewTxContent:"+ txInContent+txOutContent)
        return txInContent+txOutContent

  def get_TransactionHash(self,txIns, txOuts):
        s = hashlib.sha256()
        s.update(self.get_TransactionString(txIns, txOuts).encode("utf-8"))
        h = s.hexdigest()
        return h

  def create_coinbBaseTransaction(self, fee):

      reward = self.coinBaseAmount + fee
      senderAddr =[]
      receiverAddr = [] 
      receiverAddr.append([self.minerAddress, reward])

      try:
        latestBlock = self.get_latestBlock()
        input_txOutId = latestBlock.index +1
        senderAddr.append( [input_txOutId, 0]) #for newBlock
      except Exception:
        senderAddr.append([0, 0]) # for genesis block

      coinbBaseTx_id = self.get_TransactionHash(senderAddr, receiverAddr)
      coinbBaseTx = Transaction(coinbBaseTx_id, senderAddr, receiverAddr, reward, 0, 'coinbBaseTx')
      return coinbBaseTx

  def create_newTransaction(self, sender, receiver, amount, fee, message):
      #get_latestBalance_from_UTXOpool
      #unspentBal = self.get_latestBalance(sender)

      #get_unspentTxId_from_UTXOpool
      unspentTxIdArr, cumulative_amount = self.get_unspentTxIds(sender, amount)
      #unspentTxIdArr = [['abc',0,],['edf',0]]

      #if sender has $50, 50-10-1 =39 =change

      #get_newTxChange #change = in - out - fee
      change = cumulative_amount - amount - fee

      if change >0:
        receiverAddressArr =[[receiver,amount],[sender,change]]
      else:
        receiverAddressArr =[[receiver,amount]]
      #verify:doublespent(Txid+Index), enoughbal

      #createTxobj
      newTx_id = self.get_TransactionHash(unspentTxIdArr, receiverAddressArr)
      newTx = Transaction(newTx_id, unspentTxIdArr, receiverAddressArr, amount, fee, message)
      return newTx
##End of Transaction function


  def generate_KeyPair(self):
      public, private = rsa.newkeys(512)
      public_key = public.save_pkcs1()
      private_key = private.save_pkcs1()
      #return self.slice_pubKey(public_key)+"\n\n"+ self.slice_priKey(private_key)
      return self.slice_pubKey(public_key) , self.slice_priKey(private_key)

  def slice_pubKey(self, public):
      pubKey = str(public).replace('\\n','')
      pubKey = pubKey.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
      pubKey = pubKey.replace("-----END RSA PUBLIC KEY-----'", '')
      pubKey = pubKey.replace(' ', '')
      return pubKey

  def slice_priKey(self, private):
      priKey = str(private).replace('\\n','')
      priKey = priKey.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
      priKey = priKey.replace("-----END RSA PRIVATE KEY-----'", '')
      priKey = priKey.replace(' ', '')
      return priKey

  def generate_pubAddress(self, pubKey):#Public Key Hash 160
      sha = hashlib.sha256()
      rip = hashlib.new('ripemd160')
      sha.update(pubKey.encode("utf-8"))
      rip.update( sha.digest() )
      return rip.hexdigest()  # .hexdigest() = hex ASCII

##End of Key,Addr generate function



  def sign_transaction(self, transaction_id, private):
      full_priKey = '-----BEGIN RSA PRIVATE KEY-----\n'
      full_priKey += str(private)
      full_priKey += '\n-----END RSA PRIVATE KEY-----\n'
      #print(full_priKey)
      full_priKey_pkcs = rsa.PrivateKey.load_pkcs1(full_priKey.encode('utf-8'))

      TxId = transaction_id
      signature = rsa.sign(TxId.encode('utf-8'),full_priKey_pkcs, 'SHA-256')
      #return signature #byte format
      return self.convert_sig_BytestoHex(signature) 

  #P2PKH  : OP_DUP OP_HASH160 [Addr] OP_EQUALVERIFY OP_CHECKSIG
  def verify_transaction(self, transaction_id, hexsignature, pubKey, pubAddr):
      #1: decrypt the signature with pubkey--> get the TxId
      bytesignature = self.convert_sig_HextoBytes(hexsignature)

      full_pubKey = '-----BEGIN RSA PUBLIC KEY-----\n'
      full_pubKey += str(pubKey)
      full_pubKey += '\n-----END RSA PUBLIC KEY-----\n'
      full_pubKey_pkcs = rsa.PublicKey.load_pkcs1(full_pubKey.encode('utf-8'))

      TxId = transaction_id

      #2: regenerate the pubAddr from pubKey #[OP_DUP] [OP_HASH160]
      regen_pubAddr = self.generate_pubAddress(pubKey)
      if (regen_pubAddr == pubAddr):#[EQUALVERIFY]
        isValid_pubKey = True
      else:
        isValid_pubKey = False

      #[CHECKSIG]
      try:
        rsa.verify(TxId.encode('utf-8'), bytesignature, full_pubKey_pkcs)
        isValid_sig = True
        return isValid_sig, isValid_pubKey
        #decrypted signature == TxId 
        #for isValid_pubKey & isValid_pubKey 
      except Exception:
        return False, isValid_pubKey


  def convert_sig_BytestoHex(self, bytesignature):#for sign
     sig_BytestoHex = bytesignature.hex()
     return sig_BytestoHex

  def convert_sig_HextoBytes(self, hexsignature):#for verify
     sig_HextoBytes =bytes.fromhex(hexsignature)
     return sig_HextoBytes


  def print_Tx(self, Tx):
    input_arr =[]
    output_arr =[]

    for inObj in Tx.txIns:
          Input_dict = {
            "txOutId": inObj.txOutId,
            "txOutIndex": inObj.txOutIndex,
            "signature": inObj.signature
          }
          input_arr.append(Input_dict)

    for OutObj in Tx.txOuts:  
          Output_dict = {
            "address": OutObj.address,
            "amount": OutObj.amount
          }
          output_arr.append(Output_dict)  

    Transaction_dict = {
            'id': Tx.id,
            'input': input_arr,
            'output': output_arr,
            'amount': Tx.amount,
            'fee': Tx.fee,
            'message': Tx.message
    }
    print(Transaction_dict)

##End of signature sign,verify function


  def get_latestBalance(self, address):  #from_UTXOpool
    bal = 0
    UTXOpool_dict = self.storage.read_stateDB_UTXOpool()
    unspentRecord_array = UTXOpool_dict[address] 
    #[block.index, Tx.id, InItem.amount]
    for unspentRecord in unspentRecord_array:
      bal += unspentRecord[2]  

    return bal

  def get_unspentTxIds(self, address, amount):
    unspentTxIds_array = [] 
    cumulative_amount = 0

    UTXOpool_dict = self.storage.read_stateDB_UTXOpool()
    unspentRecord_array = UTXOpool_dict[address]
    for unspentRecord in unspentRecord_array:
      if cumulative_amount < amount:
        cumulative_amount += unspentRecord[2]
        unspentTxIds_array.append([unspentRecord[1],unspentRecord[0]])
      else:
        break
    return unspentTxIds_array, cumulative_amount 
    #[[Tx, index],[Tx, index]], cumulative_amount of input

class Storage:
  def __init__(self):
      #Tx pool:
      self.Txpool = []

      #UTXO Pool:
      self.UTXOpool = {} #Dictionary key:value =>id:

      #Full BlockChain data:
      self.rawBlockChain =[]

      self.filename = sys.argv[1] + "_DB.pickle"

  #def init_stateDB(self):
  #load Txpool,UTXOpool from stateDB --> python obj when the blockchain obj created?

  #def init_diskDB(self):
  #load rawBlockChain data from diskDB --> python obj
  def replace_diskDB_rawBlockChain(self, chain):
      self.rawBlockChain =chain
      with open(self.filename, 'wb') as handle:
        pickle.dump(self.rawBlockChain, handle, protocol=pickle.HIGHEST_PROTOCOL)

  def write_diskDB_rawBlockChain(self, newBlock):
      self.rawBlockChain.append(newBlock)
      with open(self.filename, 'wb') as handle:
        pickle.dump(self.rawBlockChain, handle, protocol=pickle.HIGHEST_PROTOCOL)
      #return self.rawBlockChain

  #call this func for getting current block level
  def read_diskDB_rawBlockChain(self): #return rawBlockChain
    with open(self.filename, 'rb') as handle:
      loaded_rawBlockChain = pickle.load(handle)
      #return self.rawBlockChain
      self.rawBlockChain = loaded_rawBlockChain
      return self.rawBlockChain

  def print_diskDB_rawBlockChain(self): #print rawBlockChain
      for block in self.rawBlockChain:
        self.print_diskDB_Block(block)

  def print_diskDB_Block(self, block):
      Tx_arr =[]
      input_arr =[]
      output_arr =[]

      for Tx in block.data:
        for inObj in Tx.txIns:
          Input_dict = {
            "txOutId": inObj.txOutId,
            "txOutIndex": inObj.txOutIndex,
            "signature": inObj.signature
          }
          input_arr.append(Input_dict)

        for OutObj in Tx.txOuts:  
          Output_dict = {
            "address": OutObj.address,
            "amount": OutObj.amount
          }
          output_arr.append(Output_dict)       


        Transaction_dict = {
            'id': Tx.id,
            'input': input_arr,
            'output': output_arr,
            'amount': Tx.amount,
            'fee': Tx.fee,
            'message': Tx.message
        }
        Tx_arr.append(Transaction_dict)
        input_arr =[]
        output_arr =[]

      Block_dict = {
        "index": str(block.index),
        "timestamp": str(block.timestamp),
        "hash": str(block.hash),
        "previousHash": str(block.previousHash),
        "difficulty": str(block.difficulty),
        "nonce": str(block.nonce),
        "merkleroot": str(block.merkleroot),#roothash
        "data": Tx_arr#all transactions record
        }
      print("\n\n")
      print(Block_dict)

  def write_stateDB_Txpool(self, TransactionObj): #push newTx, if Tx.id dup, skip
      if len(self.Txpool) >0:
        for Tx in self.Txpool:
          if Tx.id == TransactionObj.id:
            return 0
      
      self.Txpool.append(TransactionObj)

  def replace_stateDB_Txpool(self, Txpool): #for old_Txpool - new_Txpool
      self.Txpool = Txpool

  def read_stateDB_Txpool(self): #return Txpool
      return self.Txpool

  #For Class Storage internal call only,save stateDB to redis
  #def save_stateDB_Txpool(self):
      #format Txpool
      #self.Txpool

      #save to redis
      #redis_Txpool = ''

  #For Class Storage internal call only,load stateDB from redis
  #def load_stateDB_Txpool(self):
      #redis_Txpool ='' 
      #self.Txpool = redis_Txpool

  def print_stateDB_Txpool(self): #print Txpool 
      #print obj fomat
      for txitem in self.Txpool:
        print(vars(txitem))
      
      #print json format 
      #print(json.dumps())


  def read_stateDB_UTXOpool(self): #return UTXOpool
      return self.UTXOpool

  #update when there are newBlock
  def update_stateDB_UTXOpool(self): 
      self.UTXOpool ={}
      temp_spentpool ={}
      temp_unspentpool ={}

      for block in self.rawBlockChain:
        for Tx in block.data:
          #print(vars(Tx))

          #init output record
          for OutItem in Tx.txOuts:
            key = str(OutItem.address)
            value = [block.index, Tx.id, OutItem.amount]
            if key in temp_unspentpool:
              temp_unspentpool[key].append(value)#if key already exists
            else:
              temp_unspentpool[key] = []
              temp_unspentpool[key].append(value)
            
          #init input record
          for InItem in Tx.txIns:
            if not InItem.signature:
              continue

            sender_pubKey = InItem.signature[1]
            sender_address = blockchain.generate_pubAddress(sender_pubKey)

            key = str(sender_address)
            #txOutId = spentTxId 
            value = [InItem.txOutId, InItem.txOutIndex]
            if key in temp_spentpool:
              temp_spentpool[key].append(value)#if key already exists
            else:
              temp_spentpool[key] = []
              temp_spentpool[key].append(value)


      self.UTXOpool = temp_unspentpool.copy()
      #output record - input record
      #key = receiver address = sender address
      for key in set(temp_unspentpool) & set(temp_spentpool):
        #if key exists in both set, the receiver has spent some of his UTXO:        
        input_Tx =[]
        output_Tx =[]

        for InItem in temp_spentpool[key]:
          input_Tx.append(InItem[0])

        for OutItem in temp_unspentpool[key]:
          output_Tx.append(OutItem[1])

        #if Tx exists in both set, the Tx has been spent:
        #get the spent Tx list
        spent_Tx = list(set(output_Tx) & set(input_Tx))
        
        for Txid in spent_Tx:
          for OutItem in temp_unspentpool[key]:
            if OutItem[1] == Txid:
              self.UTXOpool[key].remove(OutItem)
          



            #print(vars(InItem))
  def print_stateDB_UTXOpool(self):
    UTXOpool_json = json.dumps(self.UTXOpool, indent=3)
    print(UTXOpool_json)

##############start of network section###############
class Socket_Miner:
  def __init__(self):
    self.self_host = "127.0.0.1"
    self.self_port = int(sys.argv[1])

    self.target_host = "127.0.0.1"
    self.target_port_array = [42001, 42002, 42003]


  def start_Threading(self):
      t = threading.Thread(target=self.socket_listening)
      t.start()

  def socket_listening(self):
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((self.self_host, self.self_port))
        s.listen()
        

        while True:
          conn, addr = s.accept() 
          #when connected by other node, pass conn+ addr to create thread for packet handling and message parsing
          otherNode_handler = threading.Thread(
            target=self.parse_otherNode_packet,
            args=(conn, addr)
            )          
          otherNode_handler.start()

  def parse_otherNode_packet(self, connection, address):
        with connection:
          #print('Connected by', str(address))
          otherNode_address = address[0]+":"+str(int(address[1]))
          print('\nConnected by: ')
          print(otherNode_address)

          response = b""
          #print("\nStart receiving sync data from target node" )
          while True:
            response += connection.recv(4096)
            if len(response) % 4096:
              break
          #response = connection.recv(4096)
          self.parse_packet(connection, response)
          
  def parse_packet(self, connection, response):          
        try:
          parsed_message = pickle.loads(response)
        except Exception:
          print("\nmessage cannot be parsed as pickle format")

        if parsed_message:
          #print(parsed_message)
          self.parse_case(connection, parsed_message)
          #str(response).encode('utf8')

        else:
          print("no parsed_message")


  def parse_case(self, connection, parsed_message):
        if "req_name" in parsed_message:
          name = parsed_message["req_name"]
          packet = "req"
        elif "res_name" in parsed_message:
          name = parsed_message["res_name"]
          packet = "res"
        else:
          name =''

        #for both Miner and Client node sync
        if name == "sync" and packet == "req":
            print(parsed_message)
            try:
              self_latestblock = blockchain.get_latestBlock()
              self_node_height = self_latestblock.index
            except:
              self_node_height = 0 #

            if self_node_height >0:
              UTXOpool_dict = blockchain.storage.read_stateDB_UTXOpool()
              rawBlockChain_array = blockchain.storage.read_diskDB_rawBlockChain()
              Txpool_array = blockchain.storage.read_stateDB_Txpool()
              difficulty = blockchain.difficulty
              response_dict = {
                          "res_name": "sync",
                          "Txpool": Txpool_array,
                          "UTXOpool": UTXOpool_dict,
                          "rawBlockChain": rawBlockChain_array,
                          "difficulty": difficulty,
                          "height": self_node_height


                          }
              connection.sendall(pickle.dumps(response_dict))

          #newTx request
        elif name == "create_newTx" and packet == "req":
            print(parsed_message)
            #2.1load the newTx from the nework packet(packet parsing)
            newTx = parsed_message["req_content"]
            sender = parsed_message["sender"]
            amount = newTx.amount
            fee = newTx.fee

            isValid_bal = False
            isValid_sig = False
            response_failmessage = ''
            #2.2 check bal of the sender addr from UTXO Pool
            bal =blockchain.get_latestBalance(sender)
            if (bal -amount -fee) <0:
              response_failmessage += " Not enough balance "
              isValid_bal = False
            else:
              isValid_bal = True

            #2.3 verify the signature
            sig = newTx.txIns[0].signature[0]
            pubKey = newTx.txIns[0].signature[1]
            pubAddr = sender

            isValid_sign, isValid_pubKey = blockchain.verify_transaction(newTx.id, sig, pubKey, pubAddr)
            if not isValid_sign  and not isValid_pubKey:
              response_failmessage += " Invalid signature "
              isValid_sig = False
            else:
              isValid_sig = True

            #init the response
            response_dict = {
                        "res_name": "create_newTx",
                        "res_content": '',
                        "sender": ''
                        }

            #2.4 write the newTx into stateDB            
            if isValid_sig and isValid_bal:
              #if len(blockchain.storage.read_stateDB_Txpool()) >0:
              blockchain.storage.write_stateDB_Txpool(newTx)
              print(blockchain.storage.read_stateDB_Txpool())
              response_dict["res_content"] = "\nNode: The valid new Tx has been added to the Txpool\n"
              blockchain.print_Tx(newTx)
            else:
              response_dict["res_content"] = response_failmessage +", new Tx rejected"

            print(response_dict)
            connection.sendall(pickle.dumps(response_dict))

          ######## Miner node request handling#########
          #newBlock: get new block from other node
        elif name == "publish_newBlock" and packet == "req":
            print(parsed_message)
            #-handle the newBlock message
            newblock = parsed_message["newBlock"]
            newTxpool = parsed_message["Txpool"] 
            adjustedDifficulty = parsed_message["difficulty"]

            try:            
              self_latestblock = blockchain.get_latestBlock()
              self_node_height = self_latestblock.index
              isValid_prevHash = newblock.previousHash == self_latestblock.hash
              print("isValid_prevHash: "+str(isValid_prevHash))

              recalculateHash = blockchain.get_newBlockHash( newblock.index, newblock.previousHash, newblock.timestamp, newblock.merkleroot,  newblock.nonce, newblock.difficulty)
              isValid_Hash = recalculateHash == newblock.hash              
              print("isValid_Hash: "+str(isValid_Hash))

              isValid_Height = (newblock.index - self_node_height == 1)
              print("isValid_Height: "+str(isValid_Height))
            except Exception as e:
              print(str(e))
              self_node_height = 0 #
              isValid_prevHash =False
              isValid_Hash = False
              isValid_Height = False

            if (isValid_Height) and(isValid_prevHash) and (isValid_Hash):
              #-verify the newBlock: prevHash, newBlock.hash

              #-push to the Blockchain
              blockchain.storage.write_diskDB_rawBlockChain(newblock)

              #replace self Txpool
              blockchain.storage.replace_stateDB_Txpool(newTxpool)

              #update UTXOpool
              blockchain.storage.update_stateDB_UTXOpool()

              #update difficulty
              if len(blockchain.latest_adustedDifficulty) ==0:
                blockchain.latest_adustedDifficulty.append(adjustedDifficulty)

              print("\nReceived valid newBlock, added to the chain")

              #hold: if block not expired, broadcast to another node
            else:
              print("\nReceived invalid newBlock, rejected")

            response_dict = {
                        "res_name": "publish_newBlock",
                        "res_content": str(isValid_Height)+str(isValid_prevHash)+str(isValid_Hash)
                        }
            connection.sendall(pickle.dumps(response_dict))


          ######## Miner node response handling#########
          #sync: handle the res received from ther node
          #-->get latest data from other node
        elif name == "sync" and packet == "res":
            print("\n[res_sync]: Start retrieving data from other node...")            
            #*******check wether the received data is latestd********
            other_node_height = parsed_message["height"]
            try:
              self_latestblock = blockchain.get_latestBlock()
              self_node_height = self_latestblock.index
            except:
              self_node_height = 0 #                                                                                                           

 
            if self_node_height>0 and self_node_height > other_node_height:
              #self blockchain longer than other node, do nothing
              print("\ngetting other node blockchain data...\nself.blockchain height level >= other.blockchain height level => keep self.blockchain\n")

            else:
              UTXOpool_dict = parsed_message["UTXOpool"]
              blockchain.storage.UTXOpool = UTXOpool_dict

              rawBlockChain_array = parsed_message["rawBlockChain"]
              blockchain.storage.replace_diskDB_rawBlockChain(rawBlockChain_array)

              Txpool_array =  parsed_message["Txpool"]
              blockchain.storage.Txpool = Txpool_array

              difficulty = parsed_message["difficulty"]
              #blockchain.difficulty = difficulty

              #self blockchain shorter than other node, update
              #print("\ngetting other node blockchain data...\nself.blockchain height level < other.blockchain height level => update self.blockchain\n")
              print("\ndiskDB and stateDB synchronized")

          #newBlock: get new block from other node ->valid block -> broadcast to other node
          #elif parsed_message["res_name"] == "publish_newBlock":
        else:
            print("\nNot in any message handling cases")



  def socket_sending(self, message):
      target_host = self.target_host
      target_port_array = self.target_port_array
      target_port = 42000

      
      for node_port in target_port_array:
        if node_port != self.self_port:
          try:
            target_port = int(node_port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_host, target_port))
            s.sendall(pickle.dumps(message))
            response = b""
            while True:
              response += s.recv(4096)
              if len(response) % 4096:
                break

            self.parse_packet(s, response)
            #print(response)
            s.close()
          except:
            #other node closed
            print("\nNode " +str(node_port) +" closed")


      #self.start_Threading()
      #message = "OUO"
      #s.send(message.encode())

      #get the reply from target
      #reply_message = s.recv(1024)
      #if len(reply_message) == 0: # connection closed
      #    s.close()
      #    print('target node closed connection.')
      #    #break
      #print('recv: ' + reply_message.decode())

####################
class Socket_Client:
  def __init__(self):
    self.self_host = "127.0.0.1"
    self.self_port = int(sys.argv[1])
    #self.self_port = 8001

    self.target_host = "127.0.0.1"
    self.target_port_array = [42001, 42002, 42003]

    self.s = ''

  def init_socket(self):
    target_host = self.target_host
    target_port = self.target_port_array[0]
    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.s.connect((target_host,target_port))
    

  def start_Threading(self):
    t = threading.Thread(target=self.socket_listening)
    t.start()

  #get message from node after request sent
  def socket_listening(self):
    while True:
        response = b""
        #print("\nStart receiving sync data from target node" )
        while True:
          response += self.s.recv(4096)
          if len(response) % 4096:
            break
        #self.s.close()

        #response = self.s.recv(4096)
        if response:
          print( "\nMessage from node:" )
          self.parse_packet(self.s, response)
          #print(response)

  def parse_packet(self, connection, response):
          try:
            parsed_message = pickle.loads(response)
            #print(parsed_message)
          except Exception:
            print(response)
            print("\nMessage cannot be parsed as pickle format")

          if "res_name" in parsed_message:
            #print(parsed_message)

            if parsed_message["res_name"] == "sync":
              UTXOpool_dict = parsed_message["UTXOpool"]
              blockchain.storage.UTXOpool = UTXOpool_dict

              rawBlockChain_array = parsed_message["rawBlockChain"]
              blockchain.storage.rawBlockChain = rawBlockChain_array

              #Txpool_array = = parsed_message["Txpool"]
              #blockchain.storage.Txpool = Txpool_array

              print("diskDB and stateDB synchronized")

            elif parsed_message["res_name"] == "create_newTx":
              message_newTxresult = parsed_message["res_content"]
              print(message_newTxresult)

            else:
              print("Not in any message handling cases")






  def socket_sending(self, message):
      target_host = self.target_host
      target_port_array = self.target_port_array
      target_port = 42000

      
      for node_port in target_port_array:
        if node_port != self.self_port:
          try:
            target_port = int(node_port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_host, target_port))
            s.sendall(pickle.dumps(message))
            response = b""
            while True:
              response += s.recv(4096)
              if len(response) % 4096:
                break

            self.parse_packet(s, response)
            #print(response)
            s.close()
          except:
            #other node closed
            print("\nNode " +str(node_port) +" closed")

    #self.s.sendall(pickle.dumps(message))

############ start of application level:#############



#Client mode:
class Client:
#update blockchain data from node, self_diskDB
#check if height>0 + node netork found, if not cannot enter client mode

  def __init__(self):       
      self.client_pubKey = ''
      self.client_priKey = ''
      self.client_pubAddr= ''

      self.start_clientInterface()
      
  def init_request_dict(self):
      request_dict = {
          "req_name": '',
          "req_content": ''
      }
      return request_dict

  def start_clientInterface(self):


      #Scan network, find the target node
      #init the request dict for the packet
      request_dict = self.init_request_dict()
      request_dict["req_name"] = "sync"
      node.socket_sending(request_dict)
      #-> get stateDB_UTXO, diskDB from node


      ###init KeyPair
      print("\nPlease enter your choice:\n")
      print("\n[1] Enter your own KeyPair.\n")
      print("\n[2] Generate a new KeyPair. \n")
      choice = input("Enter your choice by input the number:")


      if choice == '1':
          self.client_priKey = input("\n>Enter your private key:")
          self.client_pubKey = input("\n>Enter your public key:")
          self.client_pubAddr = input("\n>Enter your public wallet address:")
      elif choice == '2':
          self.generate_clientKeyPair()
      else:
          print("invalid input")
          return 0

      print("\nKeyPair initialized\n")



      
      #request_dict["req_name"] = "get_bal"
      #request_dict["req_name"] = "create_newTx"

      #node.socket_sending(request_dict)

      while True:
        #command menu:
        print("\nPlease enter your choice:\n")
        print("\n[1]Get the latest balance.\n")
        print("\n[2]Create a new Transacation.\n")
        print("\n[3]Sync the latest data.\n")
        choice = input("Enter your choice by input the number:")


        if choice == '1':
          bal = blockchain.get_latestBalance(self.client_pubAddr)
          print(bal)
        elif choice == '2':
          ###create newTx
          print("\nPlease enter the variable to create a newTx:")
          sender = self.client_pubAddr
          print("\nsender address:"+sender)
          receiver = input("\n>Enter the receiver of the Tx:")
          amount = input("\n>Enter the amount of the Tx:")
          fee = input("\n>Enter the fee of the Tx:")
          message = input("\n>Enter the message of the Tx:")

          self.create_clientNewTransaction(str(sender), str(receiver), int(amount), int(fee), str(message))

          #put in miner: after newTx is valid + added to new block
          #blockchain.storage.update_stateDB_UTXOpool()
        
        elif choice == '3':
          request_dict = self.init_request_dict()
          request_dict["req_name"] = "sync"
          node.socket_sending(request_dict)


        else:
          print("invalid input")

  def generate_clientKeyPair(self):  

      pubKey, priKey = blockchain.generate_KeyPair()
      pubAddr = blockchain.generate_pubAddress(pubKey)

      self.client_priKey = priKey
      self.client_pubKey = pubKey
      self.client_pubAddr = pubAddr

      print("\nprivate key:\n"  + priKey)
      print("\npublic key:\n"  + pubKey)
      print("\npublic wallet address:\n" + pubAddr)


  def create_clientNewTransaction(self, sender, receiver, amount, fee, message): 
      priKey = self.client_priKey
      pubKey = self.client_pubKey
      pubAddr = self.client_pubAddr


      #check bal of the sender addr from UTXO Pool
      #

      #create newTx
      newTx = blockchain.create_newTransaction(sender, receiver, amount, fee, message)
      #t= newTx.get_TransactionString()
      #print('\nTransaction content:' + t)
      #print('\nTransaction Hash:' + s)
      print("\nNewTxid:"+newTx.id)
      print("\n")

      #sign and verify
      sig = blockchain.sign_transaction(str(newTx.id),str(priKey))
      print("\nTransaction Signature(Hex):" +sig)

      isValid_sig, isValid_pubKey = blockchain.verify_transaction(newTx.id, sig, pubKey, pubAddr)
      print("isValid_sig:"+str(isValid_sig), ",isValid_pubKey:"+str(isValid_pubKey))


      newTx.update_TransactionSignature(sig, pubKey)
      print("\nSignature added to the new Transaction.")

      #print newTx obj
      blockchain.print_Tx(newTx)

      #send request to node for creating newTx
      request_dict = self.init_request_dict()
      request_dict["req_name"] = "create_newTx"
      request_dict["req_content"] = newTx
      request_dict["sender"] = sender      
      node.socket_sending(request_dict)
      print("newTx sent to target node")

      #test
      #request_dict["req_name"] = "test"
      #request_dict["req_content"] = "test"
      #node.socket_sending(request_dict)

      #Miner: brocast the signed newTx to other node
      #blockchain.storage.write_stateDB_Txpool(newTx)#-temp put in Miner



#Miner main:
class Miner:
  def __init__(self):

    self.start_minertInterface()

  def init_request_dict(self):
      request_dict = {
          "req_name": '',
          "req_content": ''
      }
      return request_dict

  def start_minertInterface(self):
    #
    print("\n#####start running Miner Mode######\n")
    #Prompt user input miner address
    miner_addr = input("\nEnter your wallet address to receive coinbase reward:")
    blockchain.minerAddress = miner_addr

    #>get latest data from other node
    request_dict = self.init_request_dict()
    request_dict["req_name"] = "sync"
    node.socket_sending(request_dict)#get data from other miner node
    print("\nsync request sent")




    #>check if disk file exist v+init difficulty
    try:
      blockchain.storage.read_diskDB_rawBlockChain()
      blockchain.update_difficulty()
      #update the adjusted diff from other node, and pop
      if len(blockchain.latest_adustedDifficulty) ==1:
        blockchain.difficulty =blockchain.latest_adustedDifficulty[0]
        blockchain.latest_adustedDifficulty.pop(0)
    except:
    #>if no other node + no disk file, ask user opt to create 
    #if not blockchain.storage.read_diskDB_rawBlockChain():
      #(if there are 3 terminal, only 1 user need to create and then broadcast to other)
      #print("BlockChain data not found in diskDB and other node, please input 'Y/N' to generate genesis block:")
      choice = input("\nEnter your choice to create genesis block or not:[y]/[n]")
      if choice == "y":
        print("\ngenerating genesis block...\n")
        blockchain.generate_genesisBlock()
        print("var(genesis block) = ")
        print(blockchain.storage.print_diskDB_rawBlockChain()) 

        blockchain.storage.update_stateDB_UTXOpool()
        blockchain.storage.print_stateDB_UTXOpool()
      else:
        return 0
    ###

    #Miner mode
    while True:
      #1.listen the latest request of newTx, newBlock repeatedly

      #When there are newBlock published
      #1.1 sync the stateDB, diskDB
      #1.2 Broadcast the latest info


      #When there are newTx request: 
      #2.Try to add the newTx into the Tx pool
      #2.1load the newTx from the nework packet(packet parsing)

      #2.2 check bal of the sender addr from UTXO Pool

      #2.3 verify the signature

      #2.4 write the newTx into stateDB
      #blockchain.storage.write_stateDB_Txpool(newTx)
      #blockchain.storage.print_stateDB_Txpool()

      #3.Monitor the block interval repeatedly

      #When block interval timeout: 
      #4. Try to mine the newBlock 

      #4.1 Collect all the Tx from Tx pool order by fee
      #sorted_TxList
      Tx_shortlist =[]
      Tx_shortlist = blockchain.storage.read_stateDB_Txpool().copy()
      Tx_shortlist.sort(key=lambda x: x.fee, reverse=True)

      #4.2 Avoid conflict between each Tx (No more than 1 Tx has the same sender address as the input in the same block)

      #4.3 coinbaseTx
      fee =0
      for Tx in Tx_shortlist:
        fee += int(Tx.fee)
      coinbBaseTx = blockchain.create_coinbBaseTransaction(fee)
      print("coinbBaseTx id:"+coinbBaseTx.id)
      #Tx_shortlist.insert(0, coinbBaseTx)
      #print(Tx_shortlist)
      #4.1+4.2+4.3 -> Tx_shortlist 


      #4.4 Cal the rootTxhash (delete)
      #rootTxhash = blockchain.get_merkleRoot(Tx_shortlist)
        

         
      #4.5 Generate newblock
      newblock = blockchain.generate_NextBlock(coinbBaseTx, Tx_shortlist)
      #print(newblock.hash)    
      blockchain.adjust_difficulty(newblock)

      #4.5 Write newblock into diskDB, update stateDB(delete)


      #4.6 Update Txpool(Txpool - Tx_shortlist),
      old_Txpool = blockchain.storage.read_stateDB_Txpool()
      new_Txpool = list(set(old_Txpool) - set(Tx_shortlist))
      blockchain.storage.replace_stateDB_Txpool(new_Txpool)
      #Tx_shortlist =''

      #4.7 Update UTXOpool
      blockchain.storage.update_stateDB_UTXOpool()

      #5 Broadcast the latest info: newblock, stateDB
      newblock_request_dict = self.init_request_dict()
      newblock_request_dict["req_name"] = "publish_newBlock"
      newblock_request_dict["newBlock"] = newblock
      newblock_request_dict["Txpool"] = blockchain.storage.read_stateDB_Txpool()
      #newblock_request_dict["UTXOpool"] =
      newblock_request_dict["difficulty"] = blockchain.difficulty
      node.socket_sending(newblock_request_dict)#get data from other miner node



      print("\nThe latest block info => vars(obj):")
      blockchain.storage.print_diskDB_Block(newblock)
      #blockchain.storage.print_diskDB_rawBlockChain()

      #>get latest data from other node
      request_dict = self.init_request_dict()
      request_dict["req_name"] = "sync"
      node.socket_sending(request_dict)#get data from other miner node
      print("\nsync request sent")



      #time.sleep(1.5)
      time.sleep(random.randint(1,10))
      if blockchain.get_latestBlock().index %11 ==0:
        while True:
          print("\nSelect the choice:")
          print("\n[1]Print BlockChain data")
          print("\n[2]Print stateDB")
          print("\n[3]Mine the newBlock")
          choice = input("\nEnter your choice to continue mining or not:")

          if choice=="1":
            blockchain.storage.print_diskDB_rawBlockChain()
            continue
            #print record

          elif choice=="2":
            latest_Txpool = blockchain.storage.read_stateDB_Txpool()
            print("\n\nlatest_Txpool:")
            print(latest_Txpool)

            print("\n\nlatest_UTXOpool:")
            blockchain.storage.print_stateDB_UTXOpool()

            continue
          elif choice=="3":
            break
          else:
            print("\ninvalid input")
            continue



##########Main###########

blockchain = BlockChain()



print("\nPlease select the desired mode\n")
choice = input("\nEnter your choice [1]Miner, [2]Client:")

if choice == "1":     #Miner   
  node = Socket_Miner()
  node.start_Threading()

  #miner mode
  miner = Miner()

elif choice =="2":    #Client
  node = Socket_Client()
  node.init_socket()
  node.start_Threading()


  #client mode
  client =Client()

else:
  print("invalid input")


#miner = Miner()
#client =Client()
#minerr = Miner()
################


#client and miner cannot run at the ame time, for testing only








#Print entire chain
#print("The whole blockchain vars(obj):")
#blockchain.storage.print_diskDB_rawBlockChain()

#latest_Txpool = blockchain.storage.read_stateDB_Txpool()
#print("\n\nlatest_Txpool:")
#print(latest_Txpool)

#print("\n\nlatest_UTXOpool:")
#blockchain.storage.print_stateDB_UTXOpool()





#print(vars(newTx))
#local_time = time.ctime(int(time.time()))
#print(local_time)


