import streamlit as st
import joblib
import pandas as pd
import re
import base64
from urllib.parse import urlparse
from crypto_utils import SimpleCrypto  

# Load model and features
model = joblib.load("decision_tree_phishing_model.pkl")
feature_list = joblib.load("feature_list.pkl")


# Initialize Crypto Manager
crypto = SimpleCrypto()


# Feature extraction from URL
def extract_url_features(url):
    parsed = urlparse(url)
    features = {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'https_flag': 1 if parsed.scheme == 'https' else 0,
        'num_subdirs': url.count('/') - 2,
        'num_special_chars': sum(url.count(c) for c in ['@', '-', '_', '?', '=', '&']),
        'have_ip': 1 if re.search(r'\d{1,3}(\.\d{1,3}){3}', url) else 0
    }
    return pd.DataFrame([features])[feature_list]


#  UI
st.set_page_config(page_title="Phishing URL Detector", page_icon="🔐")
st.title("Phishing URL Detector with End-to-End Encryption")
st.markdown("Enter a suspicious URL. The result will be encrypted and verified before being displayed.")

url_input = st.text_input("Enter a URL to check")


# Run encryption and prediction

if url_input:
    #  Extract features & run prediction
    features_df = extract_url_features(url_input)
    prediction = model.predict(features_df)[0]
    prob = model.predict_proba(features_df)[0][1]
    result = "Phishing " if prediction == 1 else "Legitimate "

    # AES encryption of the result
    aes_key = crypto.generate_aes_key()
    encrypted_result = crypto.aes_encrypt(aes_key, result)

    # RSA encryption of AES key
    encrypted_aes_key = crypto.rsa_encrypt(crypto.public_key, aes_key)
    decrypted_aes_key = crypto.rsa_decrypt(encrypted_aes_key)

    # HMAC-SHA256 signature of the result
    hmac_sig = crypto.compute_hmac(aes_key.decode(), result)
    hmac_valid = crypto.verify_hmac(aes_key.decode(), result, hmac_sig)

    # AES decryption for confirmation
    decrypted_result = crypto.aes_decrypt(decrypted_aes_key, encrypted_result)

    # Display results and encryption layers
    st.subheader("Prediction Result")
    st.write(f" URL Entered: `{url_input}`")
    st.write(
        f"Prediction: **{result}** (Confidence: {prob:.2%})"
        if prediction == 1
        else f"Prediction: **{result}** (Confidence: {1 - prob:.2%})"
    )

    st.subheader(" Encryption Layers")
    st.code(base64.urlsafe_b64encode(aes_key).decode(), language="text")
    st.caption("AES Key (base64 encoded)")

    st.code(encrypted_result.decode(), language="text")
    st.caption("Encrypted Result using AES (Fernet)")

    st.code(decrypted_result, language="text")
    st.caption("Decrypted Result (after AES decryption)")

    st.code(hmac_sig.decode(), language="text")
    st.caption("HMAC Signature (base64 encoded)")

    st.code(str(hmac_valid), language="text")
    st.caption("HMAC Verification Status")

    st.code(base64.urlsafe_b64encode(encrypted_aes_key).decode()[:128] + "...", language="text")
    st.caption("RSA Encrypted AES Key (base64, truncated),On the receiving side (server), AES key is decrypted with RSA")
