

# **Blockchain-Based Secure File Sharing System**

### **Overview:**  
This project builds upon the ["Blockchain-based Decentralized File Sharing System using IPFS"](https://github.com/ruchi26/Blockchain-based-Decentralized-File-Sharing-System-using-IPFS) repository. We used this as a baseline and enhanced its security features to better address the needs of closed organizations like hospitals, healthcare facilities, legal firms etc.  

Our enhancements focus on improving security attributes such as confidentiality, integrity, authentication, and non-repudiation. These improvements ensure secure and traceable file sharing while being resilient to attacks and unauthorized access.  

---

### **Key Features:**  
- Decentralized and secure file sharing using blockchain.  
- Cryptographic mechanisms to ensure data integrity and confidentiality.  
- Robust authentication and non-repudiation mechanisms for accountability.  

---

### **Features:**  
- **Confidentiality:** Only authorized users can access shared files.  
- **Integrity:** Ensures data remains unaltered during storage and transmission.  
- **Authentication:** Verifies sender and receiver identities.  
- **Non-repudiation:** Maintains an immutable record of file exchanges.  

---

### **Setup Instructions:**  

#### **Prerequisites:**  
- Python 3.9 or later installed.  
- `pip` for managing Python packages.  
- A virtual environment (optional but recommended).  

#### **Installation Steps:**  
1. **Clone the Repository**  
   Clone the project repository to your local machine:  
   ```bash
   git clone <repository-url>  
   cd blockchain-for-file-sharing  
   ```  

2. **Set Up a Virtual Environment (Optional)**  
   Create and activate a virtual environment:  
   ```bash
   python3 -m venv .venv  
   source .venv/bin/activate  # For macOS/Linux  
   .venv\Scripts\activate     # For Windows  
   ```  

3. **Install Dependencies**  
   Install the required Python packages using `requirements.txt`:  
   ```bash
   pip install -r requirements.txt  
   ```  

4. **Run the Main Server**  
   Navigate to the `main_server` directory and start the server:  
   ```bash
   cd main_server  
   python main_server.py  
   ```  

5. **Run the Client Server**  
   In another terminal, navigate to the `client_server` directory and start the client:  
   ```bash
   cd client_server  
   python client_server.py  
   ```  

---

### **Security Features:**  
- Enhanced Proof-of-Work mechanism for better security and efficiency.  
- Implemented Merkle Root Hashing to validate file integrity.  
- Enhanced Encryption using AES-GCM
- MIME Checks for File types
- Shared key mechanism for file access
- File integrity via Hashing
- Integration with IPFS for decentralized file storage
---

### **Usage:**  
This system allows users to:  
- Upload files securely to the blockchain.  
- Share files with authenticated users.  
- Verify file integrity and trace transactions through blockchain records.  

---

### **Future Improvements:**  
- Further enhance the proof of work algorithm  
- Enhance User Authentication through multi-factor authentication. 
 
### **Attacks and Security Testing:**

The following attacks were launched to test the system’s security:

1. **Proof-of-Work Forgery**  
   - **Tested Attribute:** Consensus integrity  
   - **Result:** Invalid block detected, chain marked as invalid.

2. **Replay Attack**  
   - **Tested Attribute:** Non-repudiation  
   - **Result:** Duplicate block detected, chain marked as invalid.

3. **Blockchain Tampering**  
   - **Tested Attribute:** Data integrity and authentication  
   - **Result:** Tampered block detected, chain marked as invalid.
   
These attacks confirmed the system's ability to detect and reject security threats.

---

### **Acknowledgments:**  
This project is inspired by the ["Blockchain-based Decentralized File Sharing System using IPFS"](https://github.com/ruchi26/Blockchain-based-Decentralized-File-Sharing-System-using-IPFS) repository.  

---

### **License:**  
This project is licensed under the MIT License.  

---

**Contributors:**
- [Navaira Rehman](https://github.com/NavairaRehman)
- [Aamina Binte Khurram](https://github.com/aaminaa01)


--- 