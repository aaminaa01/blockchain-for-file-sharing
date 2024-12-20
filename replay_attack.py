# Importing necessary modules
from client_server.blockchain import Blockchain

# Step 1: Initialize the Blockchain
blockchain = Blockchain()

# Step 2: Add Dummy Data to the Blockchain
blockchain.add_file(sender="Alice", receiver="Bob", file_hash="file1hash", merkle_root_hash="merkle1")
blockchain.add_file(sender="Carol", receiver="Dave", file_hash="file2hash", merkle_root_hash="merkle2")

# Display the original blockchain
print("Original Blockchain:")
for block in blockchain.chain:
    print(block)

# Replay the data of an existing block
replayed_block = blockchain.chain[1]  # Copy an existing block
blockchain.chain.append(replayed_block)  # Add it again to the chain

# Display the attacked blockchain
print("Attacked Blockchain:")
for block in blockchain.chain:
    print(block)

# Check if the chain is still valid
print("\n[Replay Attack]Is chain valid after a replay attack?:", blockchain.is_chain_valid(blockchain.chain))
