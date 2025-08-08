import streamlit as st
import joblib
import numpy as np
import pandas as pd
import sys
import os
from urllib.parse import urlparse
# Ensure crypto module is visible
#sys.path.append("")
from crypto_utils import SimpleCrypto

# -------------------------------
# Load model, scaler, and selected features
# -------------------------------
model = joblib.load("phishing_model.pkl")
scaler = joblib.load("scaler.pkl")
selected_features = joblib.load("selected_features.pkl")  # list of features

# -------------------------------
# Initialize Crypto Manager
# -------------------------------
crypto = SimpleCrypto()
aes_key = crypto.generate_aes_key()
encrypted_aes_key = crypto.rsa_encrypt(crypto.public_key, aes_key)
decrypted_aes_key = crypto.rsa_decrypt(encrypted_aes_key)

#extract URL function
def extract_features_from_url(url: str, selected_features: list):
    parsed = urlparse(url)
    netloc = parsed.netloc
    path = parsed.path
    directory = path
    file = parsed.path.split("/")[-1]
    
    features = {
        "directory_length": len(directory),
        "time_domain_activation": 0,
        "length_url": len(url),
        "qty_slash_directory": directory.count("/"),
        "ttl_hostname": 0,
        "qty_dot_file": file.count("."),
        "asn_ip": 0,
        "time_response": 0,
        "qty_dollar_directory": directory.count("$"),
        "qty_slash_url": url.count("/"),
        "time_domain_expiration": 0,
        "file_length": len(file),
        "domain_length": len(netloc),
        "qty_dot_domain": netloc.count("."),
        "qty_vowels_domain": sum(1 for c in netloc.lower() if c in "aeiou"),
        "qty_underline_directory": directory.count("_"),
        "qty_percent_directory": directory.count("%"),
        "qty_nameservers": 0,
        "qty_mx_servers": 0,
        "qty_comma_directory": directory.count(","),
        "qty_and_directory": directory.count("&"),
        "qty_at_file": file.count("@"),
        "qty_dot_directory": directory.count("."),
        "qty_ip_resolved": 0,
        "qty_dot_url": url.count("."),
        "qty_at_directory": directory.count("@"),
        "qty_plus_file": file.count("+"),
        "qty_space_file": file.count(" "),
        "qty_exclamation_directory": directory.count("!"),
        "qty_redirects": 0,
    }

    return pd.DataFrame([features])[selected_features]

# -------------------------------
# Streamlit UI
# -------------------------------
st.title("🔒 Secure Phishing Detection System")

url_input = st.text_input("Enter a URL to check:", "")

if st.button("Check URL"):
    if url_input:
        # 
        input_df = extract_features_from_url(url_input, selected_features)

        # scaler
        features_scaled = scaler.transform(input_df)

        # model prediction
        prediction = model.predict(features_scaled)[0]
        result = "Phishing 🚨" if prediction == 1 else "Legitimate ✅"

        # Encryption process
        encrypted_result = crypto.aes_encrypt(decrypted_aes_key, result)
        decrypted_result = crypto.aes_decrypt(decrypted_aes_key, encrypted_result)
        hmac_sig = crypto.compute_hmac("secret_key", result)
        hmac_valid = crypto.verify_hmac("secret_key", result, hmac_sig)

        # result
        st.subheader(" Detection Result")
        st.write(f"URL Entered: {url_input}")
        st.write(f"Prediction: **{result}**")

        st.subheader("Security Layers")
        st.write(f"🔑 **RSA Encrypted AES Key:** {encrypted_aes_key[:40]}...")
        st.write(f"🛡️ **AES Encrypted Result:** {encrypted_result[:40]}...")
        st.write(f"✅ **Decrypted Result:** {decrypted_result}")
        st.write(f"🔏 **HMAC Verified:** {hmac_valid}")
    else:
        st.warning("⚠️ Please enter a valid URL.")