import streamlit as st
import hashlib
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

st.set_page_config(page_title="Enterprise File Security System", layout="wide", page_icon="🛡️")

st.title("🛡️ Enterprise File Security Suite: Hybrid RSA-AES & Digital Signatures")
st.markdown("""
Robust implementation of **Hybrid Cryptography (AES-256-GCM + RSA-2048 OAEP)**, 
**Digital Signatures (RSA-PSS)**, and **SHA-256 Authenticated Integrity**.
""")

# ----------------- Helper Functions ----------------- #
def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def sign_data(data: bytes, sender_private_key_pem: bytes) -> bytes:
    key = RSA.import_key(sender_private_key_pem)
    h = SHA256.new(data)
    signature = pss.new(key).sign(h)
    return signature

def verify_signature(data: bytes, signature: bytes, sender_public_key_pem: bytes) -> bool:
    try:
        key = RSA.import_key(sender_public_key_pem)
        h = SHA256.new(data)
        verifier = pss.new(key)
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def encrypt_file_with_signature(file_bytes: bytes, recipient_public_key_pem: bytes, sender_private_key_pem: bytes):
    # 1. Sign original file bytes using Sender Private Key
    signature = sign_data(file_bytes, sender_private_key_pem)

    # 2. Generate 256-bit AES Session Key
    session_key = get_random_bytes(32)

    # 3. Encrypt file with AES-GCM
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_bytes)

    # 4. Encrypt session key with Recipient RSA Public Key (OAEP)
    recipient_key = RSA.import_key(recipient_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Payload Structure:
    # [2 bytes: len(enc_session_key)] + [enc_session_key]
    # [2 bytes: len(signature)] + [signature]
    # [16 bytes: nonce] + [16 bytes: tag] + [ciphertext]
    enc_key_len = len(enc_session_key).to_bytes(2, byteorder='big')
    sig_len = len(signature).to_bytes(2, byteorder='big')
    
    package = enc_key_len + enc_session_key + sig_len + signature + cipher_aes.nonce + tag + ciphertext
    return package

def decrypt_file_with_signature(encrypted_package: bytes, recipient_private_key_pem: bytes, sender_public_key_pem: bytes):
    # 1. Parse encrypted package
    offset = 0
    enc_key_len = int.from_bytes(encrypted_package[offset:offset+2], byteorder='big')
    offset += 2
    enc_session_key = encrypted_package[offset : offset + enc_key_len]
    offset += enc_key_len

    sig_len = int.from_bytes(encrypted_package[offset:offset+2], byteorder='big')
    offset += 2
    signature = encrypted_package[offset : offset + sig_len]
    offset += sig_len

    nonce = encrypted_package[offset : offset + 16]
    offset += 16
    tag = encrypted_package[offset : offset + 16]
    offset += 16
    ciphertext = encrypted_package[offset:]

    # 2. Decrypt Session Key
    recipient_key = RSA.import_key(recipient_private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # 3. Decrypt and verify payload
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # 4. Verify Digital Signature
    is_valid_sig = verify_signature(decrypted_data, signature, sender_public_key_pem)

    return decrypted_data, is_valid_sig

# ----------------- UI Layout ----------------- #
tab1, tab2, tab3 = st.tabs(["🔑 Key Management", "🔒 Secure File Encryption", "🔓 Decryption & Verification"])

# TAB 1: Key Management
with tab1:
    st.subheader("RSA 2048-bit Asymmetric Key Pairs")
    st.write("Generate cryptographic key pairs for communication parties.")
    
    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("Generate Keys for Party A (Sender)", type="primary"):
            priv_a, pub_a = generate_rsa_keypair()
            st.session_state['party_a_priv'] = priv_a
            st.session_state['party_a_pub'] = pub_a
        
        if 'party_a_priv' in st.session_state:
            st.success("Party A Keys Ready")
            st.download_button("⬇️ Download Party A Public Key", st.session_state['party_a_pub'], "party_a_public.pem")
            st.download_button("⬇️ Download Party A Private Key", st.session_state['party_a_priv'], "party_a_private.pem")

    with col_b:
        if st.button("Generate Keys for Party B (Receiver)", type="primary"):
            priv_b, pub_b = generate_rsa_keypair()
            st.session_state['party_b_priv'] = priv_b
            st.session_state['party_b_pub'] = pub_b
            
        if 'party_b_priv' in st.session_state:
            st.success("Party B Keys Ready")
            st.download_button("⬇️ Download Party B Public Key", st.session_state['party_b_pub'], "party_b_public.pem")
            st.download_button("⬇️ Download Party B Private Key", st.session_state['party_b_priv'], "party_b_private.pem")

# TAB 2: File Encryption
with tab2:
    st.subheader("Encrypt & Digitally Sign File")
    upload_file = st.file_uploader("Upload Plain File", key="enc_f")
    
    c1, c2 = st.columns(2)
    with c1:
        rec_pub_key = st.file_uploader("Upload Receiver's Public Key (.pem) [For Encryption]", key="rec_pub")
    with c2:
        snd_priv_key = st.file_uploader("Upload Sender's Private Key (.pem) [For Digital Signature]", key="snd_priv")

    if upload_file and rec_pub_key and snd_priv_key:
        file_bytes = upload_file.read()
        rec_pub_bytes = rec_pub_key.read()
        snd_priv_bytes = snd_priv_key.read()
        
        orig_hash = calculate_sha256(file_bytes)
        st.code(f"Original File SHA-256: {orig_hash}", language="text")

        if st.button("Encrypt & Sign File", type="primary"):
            try:
                start_time = time.perf_counter()
                encrypted_package = encrypt_file_with_signature(file_bytes, rec_pub_bytes, snd_priv_bytes)
                elapsed_time = (time.perf_counter() - start_time) * 1000 # in ms

                st.session_state['enc_pkg'] = encrypted_package
                st.session_state['enc_name'] = f"{upload_file.name}.enc"
                st.session_state['enc_metrics'] = {
                    'time_ms': elapsed_time,
                    'orig_size': len(file_bytes),
                    'enc_size': len(encrypted_package),
                    'throughput': (len(file_bytes) / (1024 * 1024)) / (elapsed_time / 1000) if elapsed_time > 0 else 0
                }
                st.success("File encrypted and signed successfully!")
            except Exception as e:
                st.error(f"Encryption failed: {str(e)}")

    if 'enc_pkg' in st.session_state:
        # Display Live Performance Metrics
        m = st.session_state['enc_metrics']
        st.markdown("### 📊 Performance & Cryptographic Metrics")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Execution Time", f"{m['time_ms']:.2f} ms")
        m2.metric("Throughput", f"{m['throughput']:.2f} MB/s")
        m3.metric("Original Size", f"{m['orig_size']} bytes")
        m4.metric("Package Size", f"{m['enc_size']} bytes")

        st.download_button(
            label="⬇️ Download Encrypted Signed File (.enc)",
            data=st.session_state['enc_pkg'],
            file_name=st.session_state.get('enc_name', 'data.enc'),
            mime="application/octet-stream"
        )

# TAB 3: File Decryption & Signature Verification
with tab3:
    st.subheader("Decrypt File & Verify Digital Signature")
    enc_file = st.file_uploader("Upload Encrypted File (.enc)", key="dec_f")
    
    col_x, col_y = st.columns(2)
    with col_x:
        rec_priv_key = st.file_uploader("Upload Receiver's Private Key (.pem) [To Decrypt]", key="rec_priv")
    with col_y:
        snd_pub_key = st.file_uploader("Upload Sender's Public Key (.pem) [To Verify Signature]", key="snd_pub")

    if enc_file and rec_priv_key and snd_pub_key:
        enc_data = enc_file.read()
        rec_priv_bytes = rec_priv_key.read()
        snd_pub_bytes = snd_pub_key.read()

        if st.button("Decrypt & Authenticate", type="primary"):
            try:
                start_time = time.perf_counter()
                decrypted_bytes, is_valid_sig = decrypt_file_with_signature(enc_data, rec_priv_bytes, snd_pub_bytes)
                elapsed_time = (time.perf_counter() - start_time) * 1000

                dec_hash = calculate_sha256(decrypted_bytes)
                st.session_state['dec_bytes'] = decrypted_bytes
                st.session_state['dec_hash'] = dec_hash
                st.session_state['is_valid_sig'] = is_valid_sig
                st.session_state['dec_time'] = elapsed_time
                st.session_state['orig_dl_name'] = enc_file.name.replace(".enc", "") if enc_file.name.endswith(".enc") else "restored_file"
                st.success("Decryption finished!")
            except ValueError:
                st.error("🚨 Decryption Failed! File integrity is corrupted or incorrect Private Key supplied.")
            except Exception as e:
                st.error(f"Decryption error: {str(e)}")

    if 'dec_bytes' in st.session_state:
        # Signature Authentication Status Badge
        if st.session_state['is_valid_sig']:
            st.success("✅ **Digital Signature Verified**: Sender identity is authentic and content is unaltered.")
        else:
            st.error("❌ **Invalid Digital Signature**: Warning! Sender authenticity cannot be verified.")

        d1, d2 = st.columns(2)
        d1.metric("Decryption Latency", f"{st.session_state.get('dec_time', 0):.2f} ms")
        d2.metric("Decrypted File Size", f"{len(st.session_state['dec_bytes'])} bytes")

        st.code(f"Restored File SHA-256: {st.session_state['dec_hash']}", language="text")

        st.download_button(
            label=f"⬇️️ Download Restored File ({st.session_state.get('orig_dl_name', 'restored_file')})",
            data=st.session_state['dec_bytes'],
            file_name=st.session_state.get('orig_dl_name', 'restored_file'),
            mime="application/octet-stream"
        )