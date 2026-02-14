# Read api_server.py
with open('api_server.py', 'r') as f:
    content = f.read()

# Replace authentication method
old_auth = '''def verify_api_key(x_api_key: str = Header(...)):
    """Verify API key for authentication"""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key'''

new_auth = '''def verify_api_key(authorization: str = Header(...)):
    """Verify API key for authentication (Bearer token)"""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    if token != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return token'''

content = content.replace(old_auth, new_auth)

with open('api_server.py', 'w') as f:
    f.write(content)

print("✅ API auth upgraded to Bearer token!")
