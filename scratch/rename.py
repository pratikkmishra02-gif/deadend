import os
import glob

def rename_content(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Order matters: replace longer strings first
    replacements = [
        ("deadend", "deadend"),
        ("deadend", "deadend"),
        ("Deadend AI", "Deadend AI"),
        ("Deadend", "Deadend"),
        ("deadend", "deadend"),
        ("DEADEND", "DEADEND"),
    ]
    
    new_content = content
    for old, new in replacements:
        new_content = new_content.replace(old, new)
        
    if new_content != content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated content in: {file_path}")

def rename_path(old_path):
    dirname = os.path.dirname(old_path)
    basename = os.path.basename(old_path)
    
    replacements = [
        ("deadend", "deadend"),
        ("deadend", "deadend"),
    ]
    
    new_basename = basename
    for old, new in replacements:
        new_basename = new_basename.replace(old, new)
        
    if new_basename != basename:
        new_path = os.path.join(dirname, new_basename)
        os.rename(old_path, new_path)
        print(f"Renamed {old_path} -> {new_path}")
        return new_path
    return old_path

def main():
    root_dir = "/Users/pratikmishra/Downloads/AI sec/deadend"
    
    # 1. Update file contents
    extensions = ('*.py', '*.yaml', '*.md', '*.toml')
    for ext in extensions:
        for filepath in glob.glob(os.path.join(root_dir, '**', ext), recursive=True):
            if '.venv' in filepath or '.git' in filepath or '__pycache__' in filepath:
                continue
            rename_content(filepath)
            
    # 2. Rename directories (bottom-up to avoid changing parent paths before children)
    for root, dirs, files in os.walk(root_dir, topdown=False):
        if '.venv' in root or '.git' in root:
            continue
        for name in files:
            rename_path(os.path.join(root, name))
        for name in dirs:
            rename_path(os.path.join(root, name))
            
    print("Done rebranding to Deadend!")

if __name__ == "__main__":
    main()
