from flask import Flask

# DOWNLOAD_FOLDER = r'/Users/navairarehman/Documents/Semester/Information Security /blockchain-for-file-sharing/client_server/downloads'
# TEMP_FOLDER = r"/Users/navairarehman/Documents/Semester/Information Security /blockchain-for-file-sharing/client_server/temp_folder"

DOWNLOAD_FOLDER = r"C:\Users\PMYLS\Desktop\7th semester\IS\blockchain-for-file-sharing\client_server\downloads"
TEMP_FOLDER = r"C:\Users\PMYLS\Desktop\7th semester\IS\blockchain-for-file-sharing\client_server\temp_folder"
app = Flask(__name__)
app.secret_key = "secret key"
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TEMP_FOLDER'] = TEMP_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['SERVER_IP'] = '127.0.0.1:5111'
app.config['NODE_ADDR'] = {'Host' : '127.0.0.2', 'Port' : 5113}
# app.config['NODE_ADDR'] = {'Host' : '0.0.0.0', 'Port' : 5113}
app.config['BUFFER_SIZE'] = 256 * 1024 #changed the buffer size from 64 to 256kb/512kb
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024 #allow user to upload file upto 32mb
