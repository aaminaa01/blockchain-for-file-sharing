import os
import urllib.request
import ipfshttpclient
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
    os.remove(encrypted_file_path) # Remove the encrypted file after uploading to IPFS
    return file_hash

# def retrieve_from_hash(file_hash, file_key):
#     client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
#     file_content = client.cat(file_hash)
#     file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], file_hash)
#     user_file = open(file_path, 'ab+')
#     user_file.write(file_content)
#     user_file.close()
#     decrypt_file(file_path, file_key)
#     with open(file_path, 'rb') as f:
#         lines = f.read().splitlines()
#         last_line = lines[-1]
#     user_file.close()
#     file_extension = last_line
#     saved_file = file_path + '.' + file_extension.decode()
#     os.rename(file_path, saved_file)
#     print(saved_file)
#     return saved_file

def detect_file_type(file_path):
    """Detect the MIME type using python-magic."""
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_path)

    # Fallback MIME type if detection fails
    if not mime_type:
        mime_type = 'application/octet-stream'

    return mime_type


def retrieve_from_hash(file_hash, file_key):
    client = ipfshttpclient.connect('/ip4/127.0.0.1/tcp/5001')
    file_content = client.cat(file_hash)
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

# @app.route('/add_file', methods=['POST'])
# def add_file():
    
#     is_chain_replaced = blockchain.replace_chain()

#     if is_chain_replaced:
#         print('The nodes had different chains so the chain was replaced by the longest one.')
#     else:
#         print('All good. The chain is the largest one.')

#     if request.method == 'POST':
#         error_flag = True
#         if 'file' not in request.files:
#             message = 'No file part'
#         else:
#             user_file = request.files['file']
#             if user_file.filename == '':
#                 message = 'No file selected for uploading'

#             if user_file and allowed_file(user_file.filename):
#                 error_flag = False
#                 filename = secure_filename(user_file.filename)
#                 file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#                 user_file.save(file_path)
#                 append_file_extension(user_file, file_path)
#                 sender = request.form['sender_name']
#                 receiver = request.form['receiver_name']
#                 file_key = request.form['file_key']
#                 try:
#                     hashed_output1 = hash_user_file(file_path, file_key)
#                     index = blockchain.add_file(sender, receiver, hashed_output1)
#                 except Exception as err:
#                     message = str(err)
#                     error_flag = True
#                     if "ConnectionError:" in message:
#                         message = "Gateway down or bad Internet!"
#                 # message = f'File successfully uploaded'
#                 # message2 =  f'It will be added to Block {index-1}'
#             else:
#                 error_flag = True
#                 message = 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'
    
#         if error_flag == True:
#             return render_template('upload.html' , message = message)
#         else:
#             return render_template('upload.html' , message = "File succesfully uploaded")

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
                    hashed_output1 = hash_user_file(file_path, file_key)
                    index = blockchain.add_file(request.form['sender_name'], request.form['receiver_name'], hashed_output1)
                    #remove the temporary file
                    os.remove(file_path)
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


# @app.route('/retrieve_file', methods=['POST'])
# def retrieve_file():

#     is_chain_replaced = blockchain.replace_chain()

#     if is_chain_replaced:
#         print('The nodes had different chains so the chain was replaced by the longest one.')
#     else:
#         print('All good. The chain is the largest one.')

#     if request.method == 'POST':

#         error_flag = True

#         if request.form['file_hash'] == '':
#             message = 'No file hash entered.'
#         elif request.form['file_key'] == '':
#             message = 'No file key entered.'
#         else:
#             error_flag = False
#             file_key = request.form['file_key']
#             file_hash = request.form['file_hash']
#             try:
#                 file_path = retrieve_from_hash(file_hash, file_key)
#             except Exception as err:
#                 message = str(err)
#                 error_flag = True
#                 if "ConnectionError:" in message:
#                     message = "Gateway down or bad Internet!"

#         if error_flag == True:
#             return render_template('download.html' , message = message)
#         else:
#             return render_template('download.html' , message = "File successfully downloaded")

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

        if not file_hash:
            message = 'No file hash entered.'
        elif not file_key:
            message = 'No file key entered.'
        else:
            error_flag = False
            try:
                # Retrieve and decrypt the file
                file_path, mime_type = retrieve_from_hash(file_hash, file_key)

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