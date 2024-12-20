# Importing necessary modules
import time
from client_server.blockchain import Blockchain

blockchain = Blockchain()

# Step 1: Forge a new block with an invalid proof-of-work
fake_proof = 12345  # Arbitrary number, doesn't satisfy PoW conditions
previous_block = blockchain.get_previous_block()
previous_hash = blockchain.hash(previous_block)

# Create the forged block
forged_block = {
    'index': len(blockchain.chain) + 1,
    'timestamp': str(time.strftime("%d %B %Y , %I:%M:%S %p", time.localtime())),
    'proof': fake_proof,
    'previous_hash': previous_hash,
    'sender': 'Eve',
    'receiver': 'Frank',
    'shared_files': 'fake_file_hash',
    'merkle_root': 'fake_merkle_root'
}

# Step 2: Append the forged block to the chain
blockchain.chain.append(forged_block)

# Step 3: Check if the chain is valid
print("\n[Proof-of-Work Forgery] Is chain valid after adding a forged block?:", blockchain.is_chain_valid(blockchain.chain))
