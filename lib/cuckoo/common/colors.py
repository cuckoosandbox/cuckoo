import sys

def color(text, color_code):
    if sys.platform == "win32":
        return text

    return chr(0x1b) + "[" + str(color_code) + "m" + text + chr(0x1b) + "[0m"

def black(text):
    return color(text, 30)

def red(text):
    return color(text, 31)

def green(text):
    return color(text, 32)

def yellow(text):
    return color(text, 33)

def blue(text):
    return color(text, 34)

def magenta(text):
    return color(text, 35)

def cyan(text):
    return color(text, 36)

def white(text):
    return color(text, 37)

def bold(text):
    return color(text, 1)
