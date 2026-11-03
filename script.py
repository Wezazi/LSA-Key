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
    


#Clear Secret Structure
clearSecretSize = groupByByte[0:4] #Size of the keys blob, don't forget to interpret the size value as a little endian value when converting it to decimal representation
clearUnk0 = groupByByte[4:8] #Unknown property
clearUnk1 = groupByByte[8:12] #Unknown property
clearUnk2 = groupByByte[12:16] #Unknown property

clearSecretSize = bytes.fromhex("".join(clearSecretSize))
clearSecretSize = int.from_bytes(clearSecretSize, byteorder="little") # Size of the keys blob in little endian decimal representation. byteorder="little" interprets it as little endian. For example if your clearSecretSize is 54000000 and you don't use byteorder="little", it will return decimal 1409286144 instead of 84  


keys = groupByByte[16:16 + clearSecretSize] #all bytes that aren't within this range are discarded


#Keys blob Structure
keysUnkType0 = keys[0:4] #Unknown property
keysCurrentKeyId = keys[4:20] #GUID of the current key? not sure how this would change with multiple keys though so it might be the GUID of the first key and not current key
keysUnkType1 = keys[20:24] #unknown property
keysNbKeys = keys[24:28]#number of keys in hexadecimal representation


keysNbKeys = bytes.fromhex("".join(keysNbKeys))
keysNbKeys = int.from_bytes(keysNbKeys, byteorder="little") #amount of keys in little endian decimal reprsentation


#Key blob structure
keyId = keys[28:44] #GUID of the first key
keyType = keys[44:48] #Not sure what this is 
keySize = keys[48:52] #hex size of the current key

keySize = bytes.fromhex("".join(keySize))
keySize = int.from_bytes(keySize, byteorder="little") #size of the current key in little endian decimal representation

#LSA Encrption key
lsaKey = "".join(keys[52:52+keySize])
print(f"LSA Key: {lsaKey}")

#The code doesn't currently handle cases with multiple encrpytion keys, I'll update the code once i come across it in an engagement because i currently don't know how the structure would look like with additional keys


