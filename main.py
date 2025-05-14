import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

# Constants
KEY_FILENAME = "Secret_Keyfile.key"
DB_NAME = "secure_storage.db"

# Load or generate encryption key
def get_encryption_key():
    if not os.path.isfile(KEY_FILENAME):
        new_key = Fernet.generate_key()
        with open(KEY_FILENAME, "wb") as file:
            file.write(new_key)
    else:
        with open(KEY_FILENAME, "rb") as file:
            new_key = file.read()
    return new_key

fernet = Fernet(get_encryption_key())

# Database setup
def setup_database():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                identifier TEXT PRIMARY KEY,
                encrypted_value TEXT,
                key_hash TEXT
            )
        """)
        conn.commit()

setup_database()

# Helper functions
def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_data(plain_text):
    return fernet.encrypt(plain_text.encode()).decode()

def decrypt_data(cipher_text):
    return fernet.decrypt(cipher_text.encode()).decode()

# --- UI starts ---
st.set_page_config(page_title="Secret Manager", page_icon="🔐", layout="centered")
st.markdown("<h1 style='color: #4CAF50;'>🔐 Secure Data Encryption App</h1>", unsafe_allow_html=True)
st.markdown("---")

options = ["🔒 Save Secret", "🔓 Access Secret"]
user_selection = st.sidebar.radio("Select an Option", options)

if user_selection == "🔒 Save Secret":
    st.subheader("📝 Store a New Secret")

    with st.form("save_form"):
        identifier = st.text_input("🆔 Unique Identifier")
        secret_input = st.text_area("🔑 Secret Content")
        user_key = st.text_input("🔐 Set a Passkey", type="password")
        submit_btn = st.form_submit_button("Secure & Store")

        if submit_btn:
            if identifier and secret_input and user_key:
                encrypted_secret = encrypt_data(secret_input)
                hashed_passkey = sha256_hash(user_key)

                try:
                    with sqlite3.connect(DB_NAME) as conn:
                        cursor = conn.cursor()
                        cursor.execute("INSERT INTO secrets (identifier, encrypted_value, key_hash) VALUES (?, ?, ?)",
                                       (identifier, encrypted_secret, hashed_passkey))
                        conn.commit()
                    st.success("✅ Secret stored securely!")
                except sqlite3.IntegrityError:
                    st.error("❌ Identifier already exists. Try another one.")
            else:
                st.warning("⚠️ Please fill in all fields.")

elif user_selection == "🔓 Access Secret":
    st.subheader("🔍 Retrieve Your Secret")

    with st.form("access_form"):
        input_id = st.text_input("🆔 Identifier")
        input_key = st.text_input("🔐 Enter Passkey", type="password")
        retrieve_btn = st.form_submit_button("Decrypt Secret")

        if retrieve_btn:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT encrypted_value, key_hash FROM secrets WHERE identifier = ?", (input_id,))
                record = cursor.fetchone()

            if record:
                stored_encrypted, stored_key_hash = record
                if sha256_hash(input_key) == stored_key_hash:
                    original_data = decrypt_data(stored_encrypted)
                    st.success("✅ Decryption Successful!")
                    st.code(original_data, language='text')
                else:
                    st.error("❌ Incorrect passkey.")
            else:
                st.warning("⚠️ No record found for this identifier.")
