rule Ransomware_Message
{
     meta:
         description = "A potential ransomware message was found in process memory"
         author = "Kevin Ross"

     strings:
         $message1 = "your files" nocase
         $message2 = "your data" nocase
         $message3 = "your documents" nocase
         $message4 = "restore files" nocase
         $message5 = "restore data" nocase
         $message6 = "restore the files" nocase
         $message7 = "restore the data" nocase
         $message8 = "recover files" nocase
         $message9 = "recover data"
         $message10 = "recover the files" nocase
         $message11 = "recover the data" nocase
         $message12 = "has been locked" nocase
         $message13 = "pay fine" nocase
         $message14 = "pay a fine" nocase
         $message15 = "pay the fine" nocase
         $message16 = "decrypt" nocase
         $message17 = "encrypt" nocase
         $message18 = "recover files" nocase
         $message19 = "recover data" nocase
         $message20 = "recover them" nocase
         $message21 = "recover your" nocase
         $message22 = "recover personal" nocase
         $message23 = "bitcoin" nocase
         $message24 = "secret server" nocase
         $message25 = "secret internet server" nocase
         $message26 = "install tor" nocase
         $message27 = "download tor" nocase
         $message28 = "tor browser" nocase
         $message29 = "tor gateway" nocase
         $message30 = "tor-browser" nocase
         $message31 = "tor-gateway" nocase
         $message32 = "torbrowser" nocase
         $message33 = "torgateway" nocase
         $message34 = "torproject.org" nocase
         $message35 = "ransom" nocase
         $message36 = "bootkit" nocase
         $message37 = "rootkit" nocase
         $message38 = "payment" nocase
         $message39 = "victim" nocase
         $message40 = "private key" nocase
         $message41 = "personal key" nocase
         $message42 = "your code" nocase
         $message43 = "private code" nocase
         $message44 = "personal code" nocase
         $message45 = "enter code" nocase
         $message46 = "your key" nocase
         $message47 = "unique key" nocase
         $message48 = "decrypt program" nocase
         $message49 = "decryption program" nocase
         $encryption1 = "AES128" nocase
         $encryption2 = "AES256" nocase
         $encryption3 = "AES 128" nocase
         $encryption4 = "AES 256" nocase
         $encryption5 = "AES-128" nocase
         $encryption6 = "AES-256" nocase
         $encryption7 = "RSA1024" nocase
         $encryption8 = "RSA2048" nocase
         $encryption9 = "RSA4096" nocase
         $encryption10 = "RSA 1024" nocase
         $encryption11 = "RSA 2048" nocase
         $encryption12 = "RSA 4096" nocase
         $encryption13 = "RSA-1024" nocase
         $encryption14 = "RSA-2048" nocase
         $encryption15 = "RSA-4096" nocase

     condition:
         3 of ($message*) or (2 of ($message*) and any of ($encryption*)) 
}
