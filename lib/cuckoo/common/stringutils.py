import string

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
