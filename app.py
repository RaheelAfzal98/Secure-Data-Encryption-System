# ===============================
# EncryptoVault App by Raheel Afzal (Fixed Version)
# ===============================

import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# === Persistent Encryption Key ===
if "ENCRYPTION_KEY" not in st.session_state:
    st.session_state.ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(st.session_state.ENCRYPTION_KEY)

# === Session Defaults ===
defaults = {
    "attempt_count": 0,
    "access_granted": True,
    "data_vault": {}
}
for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val

# === Utility Functions ===

def sha256_hash(input_text):
    """Hash trimmed input with SHA-256."""
    return hashlib.sha256(input_text.strip().encode()).hexdigest()

def encrypt_text(plain_text):
    """Encrypt the input text."""
    return cipher_suite.encrypt(plain_text.encode()).decode()

def decrypt_text(encrypted_data, key_input):
    """Decrypt if hashed passkey matches stored one."""
    input_hash = sha256_hash(key_input)
    for record in st.session_state.data_vault.values():
        if record["ciphertext"] == encrypted_data:
            if record["key_hash"] == input_hash:
                st.session_state.attempt_count = 0
                return cipher_suite.decrypt(encrypted_data.encode()).decode()
            break
    st.session_state.attempt_count += 1
    return None

# === Sidebar Navigation ===
with st.sidebar:
    st.title("🔐 EncryptoVault")
    selected = st.radio("Menu", ["🏡 Overview", "🗃️ Encrypt Data", "🔍 Decrypt Data", "🔑 Admin Reset"])

# === Overview ===
if selected == "🏡 Overview":
    st.header("🛡️Secure Data Encryption System")
    st.markdown("""
    - 🛡️ Encrypt sensitive info.
    - 🔐 Decrypt using a secure passkey.
    - 🚫 Locks access after 3 failed attempts.
    """)
    st.info("Use the sidebar to navigate.")

# === Encrypt Page ===
elif selected == "🗃️ Encrypt Data":
    st.header("🛡️ Secure Data Encryption")

    col1, col2 = st.columns(2)
    with col1:
        record_id = st.text_input("🆔 Unique ID")
    with col2:
        user_key = st.text_input("🔑 Passkey", type="password")

    plain_input = st.text_area("📄 Text to Encrypt", height=150)

    if st.button("🔒 Encrypt & Save"):
        if record_id and user_key and plain_input:
            if record_id in st.session_state.data_vault:
                st.warning("⚠️ That ID already exists.")
            else:
                encrypted_data = encrypt_text(plain_input)
                pass_hash = sha256_hash(user_key)
                st.session_state.data_vault[record_id] = {
                    "ciphertext": encrypted_data,
                    "key_hash": pass_hash
                }
                st.success("✅ Encrypted & stored successfully.")
                with st.expander("📦 Encrypted Output"):
                    st.code(encrypted_data)
        else:
            st.error("❌ Please fill in all fields.")

# === Decrypt Page ===
elif selected == "🔍 Decrypt Data":
    if not st.session_state.access_granted:
        st.error("🔒 Locked due to too many failed attempts.")
        st.info("Use 'Admin Reset' to restore access.")
        st.stop()

    st.header("🔍 Decrypt Stored Data")

    col1, col2 = st.columns(2)
    with col1:
        lookup_id = st.text_input("🆔 Record ID")
    with col2:
        lookup_key = st.text_input("🔑 Passkey", type="password")

    if st.button("🔓 Decrypt Now"):
        if lookup_id and lookup_key:
            if lookup_id in st.session_state.data_vault:
                encrypted = st.session_state.data_vault[lookup_id]["ciphertext"]
                result = decrypt_text(encrypted, lookup_key)
                if result:
                    st.success("✅ Decryption successful!")
                    st.code(result)
                else:
                    remaining = 3 - st.session_state.attempt_count
                    st.error(f"❌ Incorrect key. {remaining} attempt(s) left.")
                    if st.session_state.attempt_count >= 3:
                        st.session_state.access_granted = False
                        st.warning("🚫 Access locked. Restart required.")
                        st.experimental_rerun()
            else:
                st.error("⚠️ No such ID found.")
        else:
            st.error("❌ Please complete both fields.")

# === Admin Reset Page ===
elif selected == "🔑 Admin Reset":
    st.header("🔐 Restore Access")
    st.markdown("Locked out? Use master key to reset failed attempts.")

    admin_key = st.text_input("🔐 Master Password", type="password")

    if st.button("♻️ Reset Vault"):
        if admin_key == "admin123":
            st.session_state.attempt_count = 0
            st.session_state.access_granted = True
            st.success("✅ Access restored successfully.")
        else:
            st.error("❌ Incorrect master key.")

# === Footer ===
st.markdown("---")
st.markdown("© 2025 • Built with 💡 by **Raheel Afzal**")
