import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Encryption Setup (Persistent within session) ---
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

cipher = Fernet(st.session_state.fernet_key)

# --- In-Memory Storage ---
stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True

# --- Utilities ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_and_store(text, passkey):
    encrypted = cipher.encrypt(text.encode()).decode()
    hashed = hash_passkey(passkey)
    stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
    return encrypted

def try_decrypt(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    record = stored_data.get(encrypted_text)
    if record and record["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# --- App UI ---
st.set_page_config(page_title="Secure Data App", page_icon="🔒", layout="centered")
st.markdown("<h1 style='text-align: center;'>🔐 Secure Data Vault</h1>", unsafe_allow_html=True)
st.markdown("#### Store and retrieve sensitive data with encryption and passkey protection.")

# --- Navigation ---
menu = ["🏠 Home", "📥 Store Data", "🔓 Retrieve Data", "🔑 Login"]
choice = st.sidebar.radio("📋 Navigation", menu)

# --- Home Page ---
if choice == "🏠 Home":
    st.markdown("""
    ### 👋 Welcome!
    This app allows you to:
    - 🔐 Encrypt and store sensitive data
    - 🧾 Retrieve it securely with your passkey
    - 🚫 Lock access after failed attempts
    """)
    st.info("Use the sidebar to begin!")

# --- Store Data Page ---
elif choice == "📥 Store Data":
    st.markdown("### 🗂️ Store Your Secure Data")
    with st.form("store_form"):
        text = st.text_area("🔸 Enter the data to secure:")
        passkey = st.text_input("🔑 Set a passkey:", type="password")
        submit = st.form_submit_button("🔒 Encrypt & Save")

        if submit:
            if text and passkey:
                encrypted = encrypt_and_store(text, passkey)
                st.success("✅ Data encrypted and stored successfully!")
                st.code(encrypted, language='text')
            else:
                st.error("⚠️ Please enter both data and a passkey.")

# --- Retrieve Data Page ---
elif choice == "🔓 Retrieve Data":
    if not st.session_state.authorized:
        st.error("🔐 Too many failed attempts! Please log in again.")
        st.stop()

    st.markdown("### 🔍 Retrieve Your Data")
    with st.form("retrieve_form"):
        encrypted_input = st.text_area("📄 Paste your encrypted data:")
        passkey = st.text_input("🔑 Enter your passkey:", type="password")
        decrypt = st.form_submit_button("🔓 Decrypt")

        if decrypt:
            if encrypted_input and passkey:
                result = try_decrypt(encrypted_input, passkey)
                if result:
                    st.success("✅ Your decrypted data:")
                    st.code(result, language='text')
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.authorized = False
                        st.warning("🔒 You are now locked out. Go to the Login page.")
            else:
                st.error("⚠️ Please fill in both fields.")

# --- Login Page ---
elif choice == "🔑 Login":
    st.markdown("### 🔓 Master Login to Unlock")
    with st.form("login_form"):
        master_pass = st.text_input("🔐 Enter master password:", type="password")
        login = st.form_submit_button("🔑 Login")

        if login:
            if master_pass == "admin123":
                st.session_state.failed_attempts = 0
                st.session_state.authorized = True
                st.success("✅ Access restored! You can now retrieve data.")
            else:
                st.error("❌ Incorrect master password.")
