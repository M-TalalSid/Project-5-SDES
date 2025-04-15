import streamlit as st
import json
import hashlib
from cryptography.fernet import Fernet
import os

# --- Configuration & Initialization ---
KEY_FILE = "secret.key"
DATA_FILE = "data.json"
MAX_ATTEMPTS = 3

# --- Cryptography & Hashing Helpers ---
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    else:
        st.info(f"Encryption key file '{KEY_FILE}' not found. Generating a new one.")
        return generate_key()

KEY = load_key()
try:
    cipher_suite = Fernet(KEY)
except Exception as e:
    st.error(f"Failed to initialize encryption suite. Check your key file. Error: {e}")
    st.stop() # Stop execution if encryption can't be initialized

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher_suite.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    try:
        return cipher_suite.decrypt(encrypted_text.encode()).decode()
    except Exception: # Catch specific exceptions in production
        return None # Return None on decryption failure

# --- Data Persistence Helpers ---
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                content = f.read()
                return json.loads(content) if content else {}
        except json.JSONDecodeError:
            st.error(f"Error reading '{DATA_FILE}'. Starting fresh or check file integrity.")
            return {}
    else:
        return {}

def save_data(data):
    try:
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except IOError as e:
        st.error(f"Failed to save data to '{DATA_FILE}'. Error: {e}")

st.set_page_config(page_title="Secure Vault", layout="centered")

st.markdown("""
<style>
    /* Main app styling */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    /* Consistent Button Style */
    .stButton>button {
        border: none;
        border-radius: 5px;
        padding: 10px 20px;
        background-color: #046ad6; /* Primary blue */
        color: white;
        font-weight: 500;
        width: 100%; /* Full width buttons */
        transition: background-color 0.2s ease-in-out;
    }
    .stButton>button:hover {
        background-color: #0754a8; /* Darker blue on hover */
    }
    .stButton>button:focus {
        outline: none;
        box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.5);
    }
    /* Logout button specific style */
    .stButton[data-testid$="logout"]>button {
        background-color: #dc3545; /* Red for logout/destructive */
    }
    .stButton[data-testid$="logout"]>button:hover {
        background-color: #c82333;
    }
    /* Input field styling */
    .stTextInput>div>div>input, .stTextArea>div>textarea {
        border-radius: 5px;
        border: 1px solid #ced4da;
        padding: 10px;
    }
    .stTextInput>div>div>input:focus, .stTextArea>div>textarea:focus {
         border-color: #60a6f0; /* Blue focus border */
         box-shadow: 0 0 0 0.2rem rgba(0,123,255,.25);
    }
    /* Containers and Forms */
    .stForm, .stExpander {
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        padding: 1.5rem;
        background-color: #2b2b2b; /* Light background */
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        margin-bottom: 1rem;
    }
    h1 { text-align: center; color: #333; }
    h2, h3 { color: #555; margin-top: 1rem; }
    label { font-weight: 500; color: #495057; }
</style>
""", unsafe_allow_html=True)

stored_data = load_data()

# Initialize session state variables
if 'logged_in_user' not in st.session_state:
    st.session_state.logged_in_user = None
if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = {} # Tracks attempts per user {username: {'attempts': count, 'locked': bool}}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Login"

# --- Navigation Helper ---
def navigate_to(page_name):
    """Updates the current page in session state."""
    # Reset retrieval attempts when navigating away from retrieve page or logging out
    user = st.session_state.get('logged_in_user')
    if page_name != "Retrieve" and user and user in st.session_state.login_attempts:
       st.session_state.login_attempts[user]['attempts'] = 0 # Reset attempts count only
    st.session_state.current_page = page_name
    st.rerun() # Trigger a rerun to render the new page

# --- Page Rendering Functions ---
def render_login():
    """Renders the Login/Registration page."""
    st.header("🔑 User Login / Sign Up")
    st.info("Enter A Username. Login If Exists, Or Register First.")

    with st.form("login_form"):
        username_login = st.text_input("Username", key="login_username")
        # Password field primarily for conceptual alignment, not secure auth here
        password_login = st.text_input("Password", type="password", key="login_password")
        submitted_login = st.form_submit_button("Login / Register")

        if submitted_login:
            if username_login:
                st.session_state.logged_in_user = username_login
                # Initialize or reset user attempt state
                if username_login not in st.session_state.login_attempts:
                    st.session_state.login_attempts[username_login] = {'attempts': 0, 'locked': False}
                else:
                    st.session_state.login_attempts[username_login]['locked'] = False # Unlock on login
                    st.session_state.login_attempts[username_login]['attempts'] = 0 # Reset attempts on login
                st.success(f"Welcome, {username_login}!")
                navigate_to("Home")
            else:
                st.warning("Please Enter A Username.")

def render_home():
    """Renders the Home page after login."""
    user = st.session_state.logged_in_user
    if not user:
        navigate_to("Login") # Redirect if not logged in
        return

    st.header(f"🏠 Welcome, {user}!")
    st.write("Choose An Action:")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("➕ Store New Data"):
            navigate_to("Store")
    with col2:
        # Check lock status before showing retrieve button logic
        is_locked = st.session_state.login_attempts.get(user, {}).get('locked', False)
        if is_locked:
             st.error("Account Locked Due To Failed Attempts. Logout & Login Again.")
        elif st.button("🔓 Retrieve Data"):
             navigate_to("Retrieve")

    if st.button("🚪 Logout", key="logout_home", type="secondary"): # Use a unique key
         # Reset attempts and lock status on logout
         if user in st.session_state.login_attempts:
            st.session_state.login_attempts[user] = {'attempts': 0, 'locked': False}
         st.session_state.logged_in_user = None
         navigate_to("Login")

def render_store():
    """Renders the page for storing new data."""
    user = st.session_state.logged_in_user
    if not user:
        navigate_to("Login")
        return

    st.header("➕ Store New Secure Data")
    with st.form("store_data_form"):
        data_to_store = st.text_area("Enter Text Data To Encrypt:")
        passkey_store = st.text_input("Create A Passkey (Remember This !)", type="password")
        submitted_store = st.form_submit_button("Store Data")

        if submitted_store:
            if data_to_store and passkey_store:
                hashed_pk = hash_passkey(passkey_store)
                encrypted_dt = encrypt_data(data_to_store)

                if user not in stored_data:
                    stored_data[user] = {} # Initialize user's storage

                # Simple data ID generation (can be improved)
                data_id = f"data_{len(stored_data.get(user, {})) + 1}"
                stored_data[user][data_id] = {"encrypted_text": encrypted_dt, "passkey_hash": hashed_pk}

                save_data(stored_data) # Save to JSON
                st.success("Data Encrypted And Stored Successfully!")
            else:
                st.warning("Please Provide Both Data And A Passkey.")

    if st.button("⬅️ Back To Home"):
        navigate_to("Home")

def render_retrieve():
    """Renders the page for retrieving data."""
    user = st.session_state.logged_in_user
    if not user:
        navigate_to("Login")
        return

    st.header("🔓 Retrieve Your Secure Data")

    if user not in stored_data or not stored_data[user]:
        st.info("You Haven't Stored Any Data Yet.")
    else:
        # Check lock status
        user_attempts_state = st.session_state.login_attempts.get(user, {'attempts': 0, 'locked': False})
        if user_attempts_state['locked']:
            st.error(f"Maximum Retrieval Attempts ({MAX_ATTEMPTS}) Reached. Please Logout & Login Again To Retry.")
        else:
            with st.form("retrieve_data_form"):
                passkey_retrieve = st.text_input("Enter Passkey To Decrypt:", type="password")
                submitted_retrieve = st.form_submit_button("Retrieve Data")

                if submitted_retrieve:
                    if passkey_retrieve:
                        hashed_input_pk = hash_passkey(passkey_retrieve)
                        found_data = False

                        for data_id, data_item in stored_data.get(user, {}).items():
                            if data_item["passkey_hash"] == hashed_input_pk:
                                decrypted_text = decrypt_data(data_item["encrypted_text"])
                                if decrypted_text is not None:
                                    st.subheader("Decrypted Data:")
                                    st.success(f"```\n{decrypted_text}\n```") # Use success box and code block
                                    user_attempts_state['attempts'] = 0 # Reset attempts on success
                                    found_data = True
                                    break # Assume one passkey decrypts one item for simplicity
                                else:
                                    st.error("Decryption Failed. Data Might Be Corrupted Or Key Changed.")
                                    found_data = True # Indicate an attempt was made on a matching hash
                                    break

                        if not found_data:
                            user_attempts_state['attempts'] += 1
                            attempts = user_attempts_state['attempts']
                            st.warning(f"Incorrect Passkey. Attempt {attempts} of {MAX_ATTEMPTS}.")

                            if attempts >= MAX_ATTEMPTS:
                                user_attempts_state['locked'] = True
                                st.error(f"Maximum Attempts Reached! Account Locked.")
                                # Force re-login - user must explicitly log out and back in via Home/Login page now
                                # We don't automatically navigate away here to show the locked message
                                st.rerun() # Rerun to update UI state based on lock

                        # Update the main session state dictionary
                        st.session_state.login_attempts[user] = user_attempts_state

                    else:
                        st.warning("Please Enter A Passkey.")

    if st.button("⬅️ Back To Home"):
        navigate_to("Home")

st.title("🛡️ Secure Data Vault")

# Determine current user and page
current_page = st.session_state.current_page
logged_in_user = st.session_state.logged_in_user

if current_page == "Login" or not logged_in_user:
    render_login()
elif current_page == "Home":
    render_home()
elif current_page == "Store":
    render_store()
elif current_page == "Retrieve":
    render_retrieve()
else:
    # Fallback to login if state is somehow invalid
    st.warning("Invalid State. Redirecting To Login.")
    navigate_to("Login")

st.markdown("---")
st.caption("Secure Data Vault v1.1 - © 2025")
st.markdown("Made With Streamlit By Talal Shoaib")