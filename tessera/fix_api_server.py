"""Fix API server to properly load environment variables"""

with open('api_server.py', 'r') as f:
    content = f.read()

# Ensure load_dotenv() is called early
if 'load_dotenv()' not in content[:500]:
    # Add it right after imports
    import_section_end = content.find('app = FastAPI')
    if import_section_end != -1:
        new_content = content[:import_section_end] + '\nload_dotenv()\n\n' + content[import_section_end:]
        content = new_content

# Ensure API_KEY is loaded from environment
old_api_key = 'API_KEY = os.getenv(\'TESSERA_API_KEY\', \'tessera-demo-key-change-in-production\')'
new_api_key = '''# Load API key from environment
API_KEY = os.getenv('TESSERA_API_KEY')
if not API_KEY:
    raise ValueError("TESSERA_API_KEY must be set in .env file")'''

if old_api_key in content:
    content = content.replace(old_api_key, new_api_key)

with open('api_server.py', 'w') as f:
    f.write(content)

print("✅ API server fixed to use environment variables")
