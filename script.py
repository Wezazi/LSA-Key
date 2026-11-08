import subprocess

bootKey = input("Enter the bootkey value: ").strip()
bootKey = bootKey.replace(" ", "")

polekList = input("Enter the PolekList Data Value: ").strip()
polekList = polekList.replace(" ", "")

groupByByte = []
for i in range(0, len(polekList), 2): 
    groupByByte.append(polekList[i:i+2])
    

version = "".join(groupByByte[0:4]) #keep in mind this doesn't return index 0 to index 4, it returns index 0 to index 3. The ending index is always one index less than specified 
encKeyId = "".join(groupByByte[4:20])
encAlgorithm = "".join(groupByByte[20:24])
flags = "".join(groupByByte[24:28])
salt = "".join(groupByByte[28:60])
encryptedPayload = "".join(groupByByte[60:])

salt = salt * 1000

derivedKey = subprocess.run(
    ["openssl", "dgst", "-sha256", "-binary"],
    input=bytes.fromhex(bootKey) + bytes.fromhex(salt),  
    capture_output=True,
).stdout

derivedKeyHex = derivedKey.hex()

#The key should be a string of hex representation but the input should be bytes format
#https://docs.openssl.org/4.0/man1/openssl-enc/#description
decryptedPayload = subprocess.run(
    ["openssl", "enc", "-aes-256-ecb", "-d", "-K", derivedKeyHex, "-nopad"], #Almost lost my mind but thankfully adding the -nopad flag finally made everything work correctly
    input=bytes.fromhex(encryptedPayload),
    capture_output=True,
).stdout

groupByByte = []

decryptedPayloadHex = decryptedPayload.hex()


for i in range(0, len(decryptedPayloadHex), 2): 
    groupByByte.append(decryptedPayloadHex[i:i+2])
    
#Some of the properties are unknown because the structures are not from official microsoft documentation, we know about the structures thanks to reverse engineers

#CLEAR_SECRET Structure 
secretSize = groupByByte[0:4] #size of SYSTEM_KEYS structure
unk0 = groupByByte[4:8] #unknown property
unk1 = groupByByte[8:12] #unknown property
unk2 = groupByByte[12:16] #unknown property

secretSize = bytes.fromhex("".join(secretSize))
secretSize = int.from_bytes(secretSize, byteorder="little") # Size of the SYSTEM_KEYS in little endian decimal representation. byteorder="little" interprets it as little endian. For example if your secretSize is 54000000 and you don't use byteorder="little", it will return decimal 1409286144 instead of 84  

#The range of SYSTEM_KEYS 
keys = groupByByte[16:16 + secretSize] #all bytes that aren't within this range won't be used and can be discarded

#SYSTEM_KEYS Structure
unkType0 = keys[0:4] #unknown property
currentKeyId = keys[4:20] #Not sure what this is
unkType1 = keys[20:24] #unknown property
nbKeys = keys[24:28] #Number of keys (Usually only 1 key, the first key is the LSA key)

nbKeys = bytes.fromhex("".join(nbKeys))
nbKeys = int.from_bytes(nbKeys, byteorder="little") 

#SYSTEM_KEY Structure
keyId = keys[28:44] #The GUID of the LSA key
keyType = keys[44:48] #Not sure what this is
keySize = keys[48:52] #Size of the LSA key

keySize = bytes.fromhex("".join(keySize))
keySize = int.from_bytes(keySize, byteorder="little") #byteorder="little" is little endian so If keysize in hex was 20000000 it's turned into 00000020 before getting converted to decimal which makes it decimal 32 instead of 536870912

#LSA Encrption key
lsaKey = "".join(keys[52:52+keySize])
print(f"LSA Key: {lsaKey}")

