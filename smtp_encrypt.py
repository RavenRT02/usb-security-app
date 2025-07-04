# Encrypt smtp.json to smtp.enc and save the key to smtp.key

from cryptography.fernet import Fernet

# === Step 1: Load original smtp.json
with open("smtp.json", "rb") as f:
    smtp_data = f.read()

# === Step 2: Generate encryption key and save
key = Fernet.generate_key()
with open("smtp.key", "wb") as f:
    f.write(key)

# === Step 3: Encrypt JSON content
fernet = Fernet(key)
encrypted_data = fernet.encrypt(smtp_data)

# === Step 4: Save encrypted content to smtp.enc
with open("smtp.enc", "wb") as f:
    f.write(encrypted_data)

print("smtp.json has been encrypted to smtp.enc")
print("smtp.key contains the decryption key")
print("DELETE smtp.json before building .exe to avoid exposing credentials.")