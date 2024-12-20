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

# Step 3: Check Validity Before Tampering
print("\nIs chain valid before tampering?:", blockchain.is_chain_valid(blockchain.chain))

# Step 4: Tamper with the Blockchain
if len(blockchain.chain) > 1:
    blockchain.chain[1]['sender'] = "MaliciousSender"  # Tampering the second block

# Display the tampered blockchain
print("\nTampered Blockchain:")
for block in blockchain.chain:
    print(block)

# Step 5: Check Validity After Tampering
print("\n[Tampering Attack]Is chain valid after tampering?:", blockchain.is_chain_valid(blockchain.chain))
