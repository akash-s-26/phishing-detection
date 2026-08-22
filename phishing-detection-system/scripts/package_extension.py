import os
import zipfile

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
EXTENSION_DIR = os.path.join(BASE_DIR, 'chrome-extension')

OUTPUT_PATHS = [
    os.path.join(BASE_DIR, 'dist-extension', 'phishguard-ai-extension.zip'),
    os.path.join(BASE_DIR, 'frontend', 'public', 'phishguard-ai-extension.zip'),
    os.path.join(BASE_DIR, 'backend', 'phishguard-ai-extension.zip')
]

def build_extension_package():
    print("[BUILD] Packaging Chrome Extension into production ZIP...")
    
    # Exclude unnecessary dev files
    exclude_exts = {'.pyc', '.git', '.DS_Store', '.log', '.tmp'}
    
    files_to_zip = []
    for root, dirs, files in os.walk(EXTENSION_DIR):
        for file in files:
            if any(file.endswith(ext) for ext in exclude_exts):
                continue
            abs_path = os.path.join(root, file)
            rel_path = os.path.relpath(abs_path, EXTENSION_DIR)
            files_to_zip.append((abs_path, rel_path))

    for out_path in OUTPUT_PATHS:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as z:
            for abs_p, rel_p in files_to_zip:
                z.write(abs_p, rel_p)
        print(f"  [OK] Created: {out_path} ({os.path.getsize(out_path)} bytes)")

    print("[SUCCESS] Chrome Extension packaged successfully.")

if __name__ == '__main__':
    build_extension_package()
