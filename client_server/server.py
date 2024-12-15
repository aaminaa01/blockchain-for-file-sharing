import os
import urllib.request
import ipfshttpclient
from blockchain import calculate_merkle_root
from my_constants import app
import pyAesCrypt
from flask import Flask, flash, request, redirect, render_template, url_for, jsonify, after_this_request, send_file 
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, send, emit
import socket
import pickle
from blockchain import Blockchain
import requests
import socketio
import hashlib
import magic

# The package requests is used in the 'hash_user_file' and 'retrieve_from hash' functions to send http post requests.
# Notice that 'requests' is different than the package 'request'.
# 'request' package is used in the 'add_file' function for multiple actions.

sio = socketio.Client() 
client_ip = app.config['NODE_ADDR']
connection_status = False

blockchain = Blockchain()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def append_file_extension(uploaded_file, file_path):
    file_extension = uploaded_file.filename.rsplit('.', 1)[1].lower()
    user_file = open(file_path, 'a')
    user_file.write('\n' + file_extension)
    user_file.close()

def decrypt_file(file_path, file_key):
    encrypted_file = file_path + ".aes"
    os.rename(file_path, encrypted_file)
    pyAesCrypt.decryptFile(encrypted_file, file_path,  file_key, app.config['BUFFER_SIZE'])

def encrypt_file(file_path, file_key):
    pyAesCrypt.encryptFile(file_path, file_path + ".aes",  file_key, app.config['BUFFER_SIZE'])

def hash_user_file(user_file, file_key):
    encrypt_file(user_file, file_key)
    encrypted_file_path = user_file + ".aes"
    client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
    response = client.add(encrypted_file_path)
    file_hash = response['Hash']

    #remove the encrypted file
    os.remove(encrypted_file_path)

    return file_hash


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
    os.remove(merkle_file_path)
    print("hashed merle root: ", response['Hash'])
    return response['Hash']
    # response = client.add_str(merkle_root)
    # merkle_root_hash = response['Hash']
    # return merkle_root_hash


def detect_file_type(file_path):
    """Detect the MIME type using python-magic."""
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_path)

    # Fallback MIME type if detection fails
    if not mime_type:
        mime_type = 'application/octet-stream'

    return mime_type

def retrieve_merkle_root_from_ipfs(merkle_root_ipfs_hash):
    client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
    # Retrieve the file content from IPFS
    merkle_root_content = client.cat(merkle_root_ipfs_hash)  
    # Decode the content to get the Merkle root as a string
    return merkle_root_content.decode('utf-8')  

def retrieve_from_hash(file_hash, file_key):
    print("Retrieving file from IPFS...")
    client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
    print("Connected to IPFS")
    file_content = client.cat(file_hash)
    print("Retrieved file content")
    file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_hash)
    print(file_path)

    # Save the encrypted content to a temporary file
    encrypted_temp_file = file_path + "_encrypted"
    with open(encrypted_temp_file, 'wb') as f:
        f.write(file_content)
    
    # Decrypt the file to the original file path
    decrypted_file_path = file_path  # Final decrypted file path
    pyAesCrypt.decryptFile(encrypted_temp_file, decrypted_file_path, file_key, app.config['BUFFER_SIZE'])
    
    # Remove the encrypted temporary file after decryption
    os.remove(encrypted_temp_file)

    # Detect MIME type
    mime_type = detect_file_type(decrypted_file_path)
    
    # Determine the file extension from MIME type
    extension = mime_type.split('/')[1]  # Example: 'image/png' -> 'png'
    final_file_path = decrypted_file_path + '.' + extension

    # Rename the file with the correct extension
    os.rename(decrypted_file_path, final_file_path)
    
    return final_file_path, mime_type


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
                    
                    print("Chunk hashes: ", chunk_hashes)
                    merkle_root = calculate_merkle_root(chunk_hashes)
                    print("Merkle root: ", merkle_root)
                    hashed_merkle_root = hash_merkle_root(merkle_root)
                    print("Hashed Merkle root: ", hashed_merkle_root)
                    hashed_output1 = hash_user_file(file_path, file_key)

                    # Add Merkle root and file hash to blockchain
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
    
        if error_flag:
            return render_template('upload.html' , message = message)
        else:
            return render_template('upload.html' , message = "File successfully uploaded")

def verify_file_integrity(file_path, stored_merkle_root, chunk_size=1024 * 1024):
    """
    Verify the file's integrity by comparing its Merkle root.
    """
    chunk_hashes = get_file_chunks(file_path, chunk_size)
    calculated_merkle_root = calculate_merkle_root(chunk_hashes)
    print("calculated_merkle_root: ", calculated_merkle_root)
    print("stored_merkle_root: ", stored_merkle_root)
    return calculated_merkle_root == stored_merkle_root

@app.route('/retrieve_file', methods=['POST'])
def retrieve_file():
    is_chain_replaced = blockchain.replace_chain()

    if is_chain_replaced:
        print('The nodes had different chains so the chain was replaced by the longest one.')
    else:
        print('All good. The chain is the largest one.')

    if request.method == 'POST':
        error_flag = True

        file_hash = request.form.get('file_hash', '').strip()
        file_key = request.form.get('file_key', '').strip()
        merkle_root_ipfs_hash = request.form.get('merkle_root_hash', '').strip()

        if not file_hash:
            message = 'No file hash entered.'
        elif not file_key:
            message = 'No file key entered.'
        elif not merkle_root_ipfs_hash:
            message = 'No Merkle root hash entered.'
        else:
            error_flag = False
            try:
                # Retrieve and decrypt the file
                file_path, mime_type = retrieve_from_hash(file_hash, file_key)
                
                # Verify integrity
                stored_merkle_root = retrieve_merkle_root_from_ipfs(merkle_root_ipfs_hash)
                print("stored_merkle_root: ", stored_merkle_root) 
                if verify_file_integrity(file_path, stored_merkle_root):
                    print("File integrity verified.")
                    error_flag = False
                    # return send_file(file_path, as_attachment=True)
                else:
                    error_flag = True
                    print("File integrity verification failed. File may be tampered.")
                    message = 'File integrity verification failed. File may be tampered.'

                # Schedule file cleanup after serving it
                @after_this_request
                def remove_file(response):
                    try:
                        print(f"Removing file: {file_path}")
                        os.remove(file_path)
                    except Exception as e:
                        print(f"Error deleting file: {e}")
                    return response

                # Get the filename for download purposes
                file_name = os.path.basename(file_path)
            except Exception as err:
                message = str(err)
                print('error:', message)
                error_flag = True
                if "ConnectionError:" in message:
                    message = "Gateway down or bad Internet!"

        if error_flag:
            return render_template('download.html', message=message)
        else:
            # Serve the file for download
            return send_file(
                file_path,
                as_attachment=True,
                download_name=file_name
            )

# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

@sio.event
def connect():
    print('connected to server')

@sio.event
def disconnect():
    print('disconnected from server')

@sio.event
def my_response(message):
    print(pickle.loads(message['data']))
    blockchain.nodes = pickle.loads(message['data'])

@app.route('/connect_blockchain')
def connect_blockchain():
    global connection_status
    nodes = len(blockchain.nodes)
    if connection_status is False:
        sio.connect('http://'+app.config['SERVER_IP'])
        sio.emit('add_client_node', 
                {'node_address' : client_ip['Host'] + ':' + str(client_ip['Port'])}
                )
        nodes = nodes + 1

    is_chain_replaced = blockchain.replace_chain()
    connection_status = True
    return render_template('connect_blockchain.html', messages = {'message1' : "Welcome to the services page",
                                                                  'message2' : "Congratulations , you are now connected to the blockchain.",
                                                                 } , chain = blockchain.chain, nodes = nodes)

@app.route('/disconnect_blockchain')
def disconnect_blockchain():
    global connection_status
    connection_status = False
    sio.emit('remove_client_node', 
            {'node_address' : client_ip['Host'] + ':' + str(client_ip['Port'])}
            )
    sio.disconnect()
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host = client_ip['Host'], port= client_ip['Port'])