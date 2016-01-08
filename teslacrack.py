# -*- coding: utf-8 -*-
# TeslaCrypt cracker
#
# by Googulator
# 
# To use, factor the 2nd hex string found in the headers of affected files using msieve.
# The AES-256 key will be one of the factors, typically not a prime - experiment to see which one works.
# Insert the hex string & AES key below, under known_keys, then run on affected directory.
# If an unknown key is reported, crack that one using msieve, then add to known_keys and re-run.
#
# This script requires pycrypto to be installed.
#
# Enjoy! ;)

from __future__ import print_function
import sys
import os
import posixpath
from Crypto.Cipher import AES
import struct
# türkçe harflere sahip dosya isimlerinde sorun olmasın diye...
reload(sys)
sys.setdefaultencoding('iso-8859-9')

# Add your key(s) here.
known_keys = {
    b'D4E0010A8EDA7AAAE8462FFE9562B29871B9DA186D98B5B15EC9F77803B60EAB12ADDF78CBD4D9314A0C31270CC8822DCC071D10193D1E612360B26582DAF124': b'\xEA\x68\x5A\x3C\xDB\x78\x0D\xF2\x12\xEB\xAA\x50\x03\xAD\xC3\xE1\x04\x06\x3E\xBC\x25\x93\x52\xC5\x09\x88\xB7\x56\x1A\xD1\x34\xA5',
    b'9F2874FB536C0A6EF7B296416A262A8A722A38C82EBD637DB3B11232AE0102153C18837EFB4558E9E2DBFC1BB4BE799AE624ED717A234AFC5E2F8E2668C76B6C': b'\xCD\x0D\x0D\x54\xC4\xFD\xB7\x64\x7C\x4D\xB0\x95\x6A\x30\x46\xC3\x4E\x38\x5B\x51\xD7\x35\xD1\x7C\x00\x9D\x47\x3E\x02\x84\x27\x95',
    b'115DF08B0956AEDF0293EBA00CCD6793344D6590D234FE0DF2E679B7159E8DB05F960455F17CDDCE094420182484E73D4041C39531B5B8E753E562910561DE52': b'\x1A\xDC\x91\x33\x3E\x8F\x6B\x59\xBB\xCF\xB3\x34\x51\xD8\xA3\xA9\x4D\x14\xB3\x84\x15\xFA\x33\xC0\xF7\xFB\x69\x59\x20\xD3\x61\x8F',
    b'3140144178AD2D5293E852378484383258B1C2839F93ACCDF2CD437B68EB199FB8AC3C3AF32A392C50C0FE81A8DC63E837589F8391DC6A49AD5CAE29C18BC9B3': b'\x44\xe3\xe4\xa9\xbc\x31\x47\x12\x8e\xc6\xc1\x09\x0f\xdd\x74\xdd\xae\xac\xd3\xe4\x77\xb2\x2b\xec\xd8\x28\xd6\x34\x2d\x82\xfd\xdd',
    b'2FEA4A2A7D78C9392D0F0624247807E634A26FE3CDB5A3FCF162C6CAB05B7512C187833155EC2B389DDB570E1E5B5CED0398719AA7FC1452D7EB469588D37AE1': b'\xe4\x97\x7c\xba\x43\x42\x12\x21\xfc\x56\xf5\x59\x76\xba\x56\xd3\xd1\x31\xce\x0a\xc2\x91\xb2\x9c\x75\xce\xd5\xf8\x77\x00\xf8\xc9',
    b'15F7E146E5E06083A71ED022296F25DBA6DEDABA68EEF3BAA0D25FFA08FD6F2EFFFDC0EFE3D307FCF5D0AD98765CF22CBB5F1D24F8E6C296841D546305B32B80': b'\x2a\xef\x36\xdd\x01\x5c\x26\x93\xbe\xb9\xcb\xed\x47\x75\xf0\x47\x45\x1f\x7c\x18\x11\xbe\xd7\xd6\x29\xc5\xca\xc9\x55\x17\x7d\xa2',
    b'3C2C545902E894281ED400B069BF5BAD1FD5A940D0FF92FB98A62987BEB3E465257AE66D55FE4510E040EDC2A00E3CB79CD0E6932B609BCDB46047AE51CB45C0': b'\x64\x8a\xb2\x9e\x12\x4d\x46\x2d\x3f\xcb\x3c\x92\xa6\x54\x78\x34\x6e\x96\x0b\xe8\x8d\x2e\x4f\xf5\xcd\x9a\x02\x90\x53\xdf\x17\x75',
    b'88D65B6BC264231B9C6E540A0E22A01BC661B1B2541ED0C2244D950A5568131C9A746AB2B0F34D17988A82E2D730F724CCFEA44929ED26C7ADF23FEACDBF4203': b'\x8c\x00\xa5\x66\x68\xd6\x0e\x89\x3c\x04\xad\x15\x4d\xd4\x22\x12\x7f\xaf\x82\x6e\x3e\x8f\x89\x3c\xe2\x6c\xd9\xd7\xef\x24\x6f\x27',    
    b'146153BECBE89A01789099938B2D68D13A1D10DD8E684664B157ACDBA66CAEB52F1E950FEF1DC3E7D90DE35DD90EA0DDF543D407D950174B97A7D8537AC6D6E1': b'\xe7\x03\xdd\x05\x27\x32\x2e\xc6\x35\x6f\xe7\x55\x92\xc6\xb4\x02\x05\x26\xf8\x0c\xd7\x60\xf6\xda\xf1\xd0\xd4\x5b\xd5\x5d\xfc\x95'
}

extensions = ('.aaa', '.vvv', '.ccc')
# tesla crypt ile şifrelenen dosyaların bilinen başlanğıç değerleri
known_file_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']
# açılabildi ise şifreli dosyayı sil
delete = False

unknown_keys = {}

unknown_btkeys = {}

def fix_key(key):
    while key[0] == b'\0':
        key = key[1:] + b'\0'
    return key

def decrypt_file(path):
    try:
        # bu dosya için silme işlemi gerçekleştirilecek mi?
        do_unlink = False
        # şifreli dosya aç 
        with open(path, "rb") as fin:
            # ve ilk 414 bytelık headar bilgisini oku
            header = fin.read(414)
            # ilk beş byte ı kontrol et (teslaCrypt in aynı versiyonu için aynı olması lazım)
            if header[:5] not in known_file_magics:
                print(path + " desteklenen bir TeslaCrypt ile crypt edilmemis.")
                return
            
            if header[0x108:0x188].rstrip(b'\0') not in known_keys:
                if header[0x108:0x188].rstrip(b'\0') not in unknown_keys:
                    unknown_keys[header[0x108:0x188].rstrip(b'\0')] = path
                #if header[0x45:0xc5].rstrip(b'\0') not in unknown_btkeys:
                #    unknown_btkeys[header[0x45:0xc5].rstrip(b'\0')] = path
                print("Decrypt islemi basarisiz {}, bilinmeyen anahtar".format(path))
                return
            
            decryptor = AES.new(fix_key(known_keys[header[0x108:0x188].rstrip(b'\0')]), AES.MODE_CBC, header[0x18a:0x19a])
            size = struct.unpack('<I', header[0x19a:0x19e])[0]
            
            if not os.path.exists(os.path.splitext(path)[0]):
                print("Decrypting {}".format(path))
                fout = open(os.path.splitext(path)[0], 'wb')
                data = fin.read()
                fout.write(decryptor.decrypt(data)[:size])
                if delete:
                    do_unlink = True
            else:
                print("Decrypt yapilmiyor {}, decrypt edilmis hali zaten mevcut".format(path))
        if do_unlink:
            os.unlink(path)
    except Exception:
        print("Decrypt hatası {}, lutfen yeniden deneyin".format(path))
        
def traverse_directory(path):
    try:
        if os.path.isfile(path):
            decrypt_file(path)
            return
        for entry in os.listdir(path):
            if os.path.isdir(posixpath.join(path, entry)):
                traverse_directory(posixpath.join(path, entry))
            # TODO add other known extensions
            elif entry.endswith(extensions) and os.path.isfile(posixpath.join(path, entry)):
                decrypt_file(posixpath.join(path, entry))
    except Exception as e:
        print("Ulasilamiyor: " + path)
    
def main(args):
    path = '.'
    global delete
    
    for arg in args:
        if arg == "--sil":
            delete = True
        else:
            path = arg

    traverse_directory(path)
    if unknown_keys:
        # print("Software has encountered the following unknown AES keys, please crack them first using msieve:")
        print("Uygulama bilinmeyen AES anahtarlarina rastladi:")
        for key in unknown_keys:
            print(key.decode() + " found in " + unknown_keys[key])
        #print("Alternatively, you can crack the following Bitcoin key(s) using msieve, and use them with TeslaDecoder:")
        #for key in unknown_btkeys:
            #print(key.decode() + " found in " + unknown_btkeys[key])
    
if __name__=='__main__':
    main(sys.argv[1:])
