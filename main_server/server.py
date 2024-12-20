import os
import urllib.request
import ipfshttpclient
from my_constants import app
import pyAesCrypt
from flask import Flask, flash, request, redirect, render_template, url_for, jsonify, send_file,after_this_request
from flask_socketio import SocketIO, send, emit
from werkzeug.utils import secure_filename
import socket
import pickle
from blockchain import Blockchain
import requests
import hashlib
from blockchain import calculate_merkle_root
import magic
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt
from os import urandom

# The package requests is used in the 'hash_user_file' and 'retrieve_from hash' functions to send http post requests.
# Notice that 'requests' is different than the package 'request'.
# 'request' package is used in the 'add_file' function for multiple actions.

socketio = SocketIO(app)
blockchain = Blockchain()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def append_file_extension(uploaded_file, file_path):
    file_extension = uploaded_file.filename.rsplit('.', 1)[1].lower()
    user_file = open(file_path, 'a')
    user_file.write('\n' + file_extension)
    user_file.close()

def decrypt_file(file_path, file_key):
    # Read the encrypted file
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Extract salt (16 bytes), IV (16 bytes), and encrypted data from the file
    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]

    # Derive the key using scrypt (using the file_key and the extracted salt)
    key = scrypt(file_key.encode(), salt, key_len=32, N=2**14, r=8, p=1)

    # Initialize AES cipher with CBC mode, derived key, and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the data
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # Write the decrypted data to a new file (e.g., remove '.aes' extension)
    decrypted_file_path = file_path.replace('.aes', '_decrypted')
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    print("File has been decrypted")
    return decrypted_file_path

# def decrypt_file(file_path, file_key):
#     encrypted_file = file_path + ".aes"
#     os.rename(file_path, encrypted_file)
#     pyAesCrypt.decryptFile(encrypted_file, file_path,  file_key, app.config['BUFFER_SIZE'])

# def encrypt_file(file_path, file_key):
#     pyAesCrypt.encryptFile(file_path, file_path + ".aes",  file_key, app.config['BUFFER_SIZE'])

def encrypt_file(file_path, file_key):
    # Generate a random salt (16 bytes) and IV (16 bytes)
    salt = urandom(16)
    iv = urandom(16)

    # Derive a key using scrypt from the password (file_key) and salt
    key = scrypt(file_key.encode(), salt, key_len=32, N=2**14, r=8, p=1)

    # Initialize AES cipher with CBC mode and the derived key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Read the file data
    with open(file_path, 'rb') as f:
        data = f.read()

    # Pad the data to make it a multiple of AES block size
    padded_data = pad(data, AES.block_size)

    # Encrypt the data
    encrypted_data = cipher.encrypt(padded_data)

    # Write the salt, IV, and encrypted data to the file
    encrypted_file_path = file_path + ".aes"
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)
    print("file has been encrypted")

    return encrypted_file_path

# def hash_user_file(user_file, file_key):
#     encrypt_file(user_file, file_key)
#     encrypted_file_path = user_file + ".aes"
#     client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
#     response = client.add(encrypted_file_path)
#     file_hash = response['Hash']
#     # print("file hash: ", file_hash)

#     os.remove(encrypted_file_path)

#     return file_hash

def hash_user_file(user_file, file_key):
    # Encrypt the file with the advanced encryption
    encrypted_file_path = encrypt_file(user_file, file_key)

    # Add the encrypted file to IPFS
    client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
    response = client.add(encrypted_file_path)
    file_hash = response['Hash']

    # Clean up the encrypted file
    os.remove(encrypted_file_path)

    return file_hash

def get_file_chunks(file_path, chunk_size=1024 * 1024):
    """
    Split a file into chunks of given size and return their hashes.
    """
    chunk_hashes = []
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            chunk_hash = hashlib.sha256(chunk).hexdigest()
            chunk_hashes.append(chunk_hash)
    return chunk_hashes

def detect_file_type(file_path):
    """Detect the MIME type using python-magic."""
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_path)

    # Fallback MIME type if detection fails
    if not mime_type:
        mime_type = 'application/octet-stream'

    return mime_type


# def retrieve_from_hash(file_hash, file_key):
#     client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
#     file_content = client.cat(file_hash)
#     file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_hash)
    
#     # Save the encrypted content to a temporary file
#     encrypted_temp_file = file_path + "_encrypted"
#     with open(encrypted_temp_file, 'wb') as f:
#         f.write(file_content)
    
    
#     # Decrypt the file to the original file path
#     decrypted_file_path = file_path  # Final decrypted file path
#     pyAesCrypt.decryptFile(encrypted_temp_file, decrypted_file_path, file_key, app.config['BUFFER_SIZE'])
    
#     # Remove the encrypted temporary file after decryption
#     # os.remove(encrypted_temp_file)

#     # Detect MIME type
#     mime_type = detect_file_type(decrypted_file_path)

#     # Determine the file extension from MIME type
#     extension = mime_type.split('/')[1]  # Example: 'image/png' -> 'png'
#     final_file_path = decrypted_file_path + '.' + extension

#     # Rename the file with the correct extension
#     os.rename(decrypted_file_path, final_file_path)
    
#     return final_file_path, mime_type

def retrieve_from_hash(file_hash, file_key):
    client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
    file_content = client.cat(file_hash)
    file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_hash)
    
    # Save the encrypted content to a temporary file
    encrypted_temp_file = file_path + "_encrypted"
    with open(encrypted_temp_file, 'wb') as f:
        f.write(file_content)
    
    try:
        # Decrypt the file using the updated decryption function
        decrypted_file_path = decrypt_file(encrypted_temp_file, file_key)
        
        # Remove the encrypted temporary file after decryption
        # os.remove(encrypted_temp_file)

        # Detect MIME type
        mime_type = detect_file_type(decrypted_file_path)

        # Determine the file extension from MIME type
        extension = mime_type.split('/')[1]  # Example: 'image/png' -> 'png'
        final_file_path = decrypted_file_path + '.' + extension

        # Rename the file with the correct extension
        os.rename(decrypted_file_path, final_file_path)
    
        return final_file_path, mime_type

    except Exception as err:
        # Handle any decryption errors
        os.remove(encrypted_temp_file)  # Clean up the temporary file
        raise err

def retrieve_merkle_root_from_ipfs(merkle_root_ipfs_hash):
    client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
    merkle_root_content = client.cat(merkle_root_ipfs_hash)  # Retrieve the file content from IPFS
    return merkle_root_content.decode('utf-8')  # Decode the content to get the Merkle root as a string

def hash_merkle_root(merkle_root):
    print("Hashing Merkle root...")
    print("merkle_root: ", merkle_root)
    # Puts merkle root on IPFS and returns the hash
    client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
    merkle_file_path = merkle_root+".txt"
    with open(merkle_file_path, 'w') as f:
        f.write(merkle_root)
    client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
    response = client.add(merkle_file_path)
    print("hashed merle root: ", response['Hash'])
    os.remove(merkle_file_path)
    return response['Hash']

def verify_file_integrity(file_path, stored_merkle_root, chunk_size=1024 * 1024):
    """
    Verify the file's integrity by comparing its Merkle root.
    """
    chunk_hashes = get_file_chunks(file_path, chunk_size)
    calculated_merkle_root = calculate_merkle_root(chunk_hashes)
    return calculated_merkle_root == stored_merkle_root


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/upload')
def upload():
    return render_template('upload.html' , message = "Welcome!")

@app.route('/download')
def download():
    return render_template('download.html' , message = "Welcome!")

@app.route('/connect_blockchain')
def connect_blockchain():
    is_chain_replaced = blockchain.replace_chain()
    return render_template('connect_blockchain.html', chain = blockchain.chain, nodes = len(blockchain.nodes))

@app.errorhandler(413)
def entity_too_large(e):
    return render_template('upload.html' , message = "Requested Entity Too Large!")

@app.route('/add_file', methods=['POST'])
def add_file():
    
    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        print('The nodes had different chains so the chain was replaced by the longest one.')
    else:
        print('All good. The chain is the largest one.')

    if request.method == 'POST':
        error_flag = True
        if 'file' not in request.files:
            message = 'No file part'
        else:
            user_file = request.files['file']
            if user_file.filename == '':
                message = 'No file selected for uploading'

            if user_file and allowed_file(user_file.filename):
                error_flag = False
                filename = secure_filename(user_file.filename)
                file_key = request.form['file_key']

                # Directly process the file without saving it in the upload folder
                try:
                    file_path = os.path.join(app.config['TEMP_FOLDER'], filename)  # Save temporarily in memory
                    user_file.save(file_path)  # Save to the temporary folder just for processing
                    
                    # Generate chunk hashes
                    encrypt_file(file_path, file_key)  # Encrypt before chunking
                    chunk_hashes = get_file_chunks(file_path)  
                    print("file path: ", file_path)
                    merkle_root = calculate_merkle_root(chunk_hashes)
                    
                    hashed_merkle_root = hash_merkle_root(merkle_root)
                    print("Hashed Merkle Root: ", hashed_merkle_root)
                    hashed_output1 = hash_user_file(file_path, file_key)

                    # Add Merkle root to blockchain
                    index = blockchain.add_file(request.form['sender_name'], request.form['receiver_name'], hashed_output1, hashed_merkle_root)
                    
                    os.remove(file_path)  # Clean up temporary file
                    
                    # hashed_output1 = hash_user_file(file_path, file_key)
                    # index = blockchain.add_file(request.form['sender_name'], request.form['receiver_name'], hashed_output1)
                    # #remove the temporary file 
                    # os.remove(file_path)
                except Exception as err:
                    message = str(err)
                    error_flag = True
                    if "ConnectionError:" in message:
                        message = "Gateway down or bad Internet!"
            else:
                error_flag = True
                message = 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'
        
        if error_flag == True:
            return render_template('upload.html' , message = message)
        else:
            return render_template('upload.html' , message = "File succesfully uploaded")


@app.route('/retrieve_file', methods=['POST'])
def retrieve_file():
    error_flag = False
    message = ""
    
    file_hash = request.form.get('file_hash', '').strip()
    file_key = request.form.get('file_key', '').strip()
    merkle_root_ipfs_hash = request.form.get('merkle_root_hash', '').strip()

    if not file_hash:
        message = 'No file hash entered.'
        error_flag = True
    elif not file_key:
        message = 'No file key entered.'
        error_flag = True
    elif not merkle_root_ipfs_hash:
            message = 'No Merkle root hash entered.'
    else:
        try:
            # Retrieve and decrypt the file
            file_path, mime_type = retrieve_from_hash(file_hash, file_key)
            
            # Verify integrity
            stored_merkle_root = retrieve_merkle_root_from_ipfs(merkle_root_ipfs_hash)

            if verify_file_integrity(file_path, stored_merkle_root):
                error_flag = False
                # return send_file(file_path, as_attachment=True)
            else:
                error_flag = True
                message = 'File integrity verification failed. File may be tampered.'
                
            # Schedule file cleanup after serving it
            @after_this_request
            def remove_file(response):
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"Error deleting file: {e}")
                return response

            # Get the filename for download purposes
            file_name = os.path.basename(file_path)

        except Exception as err:
            message = str(err)
            error_flag = True
            if "ConnectionError:" in message:
                message = "Gateway down or bad Internet!"

    if error_flag:
        return render_template('download.html', message=message)
    else:
        # Serve the file with the correct MIME type
        return send_file(
            file_path,
            as_attachment=True,
            download_name=file_name,
            mimetype=mime_type
        )


# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    print(request)

@socketio.on('add_client_node')
def handle_node(client_node):
    print(client_node)
    blockchain.nodes.add(client_node['node_address'])
    emit('my_response', {'data': pickle.dumps(blockchain.nodes)}, broadcast = True)

@socketio.on('remove_client_node')
def handle_node(client_node):
    print(client_node)
    blockchain.nodes.remove(client_node['node_address'])
    emit('my_response', {'data': pickle.dumps(blockchain.nodes)}, broadcast = True)

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    print(request)

if __name__ == '__main__':
    socketio.run(app, host = '0.0.0.0', port= 5111)
    # socketio.run(app, host = '127.0.0.1', port= 5111)