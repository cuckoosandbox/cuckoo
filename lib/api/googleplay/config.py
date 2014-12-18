# separator used by search.py, categories.py, ...
SEPARATOR = ";"

LANG            = "en_US" # can be en_US, fr_FR, ...
ANDROID_ID      = "373ed1cfed71a4c5" # "xxxxxxxxxxxxxxxx"
GOOGLE_LOGIN    = "mrllab2013@gmail.com" # "username@gmail.com"
GOOGLE_PASSWORD = "idanofer"
AUTH_TOKEN      = None # "yyyyyyyyy"

# force the user to edit this file
if any([each == None for each in [ANDROID_ID, GOOGLE_LOGIN, GOOGLE_PASSWORD]]):
    raise Exception("config.py not updated")

