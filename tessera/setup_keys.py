#!/usr/bin/env python3
"""
Setup Tessera IAM keys for development
"""
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_keypair():
    """Generate RSA keypair for development"""
    # Create keys directory
    os.makedirs('keys', exist_ok=True)
    
    private_path = 'keys/private_key.pem'
    public_path = 'keys/public_key.pem'
    
    # Generate private key
    print("🔑 Generating RSA keypair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Smaller for dev, use 4096 for production
        backend=default_backend()
    )
    
    # Save private key
    with open(private_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    public_key = private_key.public_key()
    with open(public_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print(f"✅ Private key: {private_path}")
    print(f"✅ Public key: {public_path}")
    
    # Create .env file if not exists
    if not os.path.exists('.env'):
        print("📝 Creating .env file...")
        with open('.env', 'w') as f:
            f.write(
                "TESSERA_SECRET_KEY="
                "168595de6449925806d7b448d132a5ec6290cb0ce31f253826c2694586f05c0d"
                "21518555e12dc87de7088820e215aa2505008d87d8a64ce03f2cad74d8484b06\n"
            )
            f.write("KEY_PROVIDER=local\n")
        print("✅ .env file created")

if __name__ == "__main__":
    generate_keypair()
