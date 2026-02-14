import re

# Read the file
with open('tessera/token_generator.py', 'r') as f:
    content = f.read()

# Find and replace the jwt.decode call
old_decode = '''            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'require': ['exp', 'iat', 'sub', 'tool']
                }
            )'''

new_decode = '''            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'require': ['exp', 'iat', 'sub', 'tool']
                },
                leeway=10  # Allow 10s clock skew
            )'''

content = content.replace(old_decode, new_decode)

# Write back
with open('tessera/token_generator.py', 'w') as f:
    f.write(content)

print("✅ Clock skew fixed!")
