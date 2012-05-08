import os
import string
import hashlib

try:
    import magic
except ImportError:
    pass

def create_folders(root=".", folders=[]):
    for folder in folders:
        if os.path.exists(folder):
            continue

        try:
            folder_path = os.path.join(root, folder)
            os.makedirs(folder_path)
        except OSError as e:
            continue

def get_file_type(file_path):
    if not os.path.exists(file_path):
        return None
    
    data = open(file_path, "rb").read()

    try:
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        file_type = ms.buffer(data)
    except:
        try:
            file_type = magic.from_buffer(data)
        except:
            try:
                import subprocess
                file_process = subprocess.Popen(['file', '-b', file_path], stdout = subprocess.PIPE)
                file_type = file_process.stdout.read().strip()
            except:
                return None

    return file_type

def get_file_md5(file_path):
    if not os.path.exists(file_path):
        return None

    file_data = open(file_path, "rb").read()
    return hashlib.md5(file_data).hexdigest()

def convert_char(c):
    if c in string.ascii_letters or \
       c in string.digits or \
       c in string.punctuation or \
       c in string.whitespace:
        return c
    else:
        return r'\x%02x' % ord(c)

def convert_to_printable(s):
    return ''.join([convert_char(c) for c in s])
