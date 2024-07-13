#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>

using namespace CryptoPP;
using namespace std;

// Function to perform DES decryption with CBC mode and PKCS7 padding
string DecryptData(const string& encryptedData, const string& key) {
    byte iv[DES::BLOCKSIZE] = { 0 }; // Initialization Vector

    // Prepare key and IV
    SecByteBlock byteKey((const byte*)key.data(), DES::DEFAULT_KEYLENGTH);

    // Decryptor setup
    CBC_Mode<DES>::Decryption decryptor;
    decryptor.SetKeyWithIV(byteKey, byteKey.size(), iv);

    // Decode Base64 and decrypt
    string decryptedData;
    StringSource(encryptedData, true,
        new Base64Decoder(
            new StreamTransformationFilter(decryptor,
                new StringSink(decryptedData)
            )
        )
    );

    return decryptedData;
}

int main() {
    // File paths
    string encryptedFilePath = "output.txt"; // Adjust path as needed
    string decryptedOutputFilePath = "decrypted_output.txt"; // Adjust path as needed
    string key = "56410841"; // Encryption key (must match the key used for encryption)

    // Open encrypted input file
    ifstream encryptedInputFile(encryptedFilePath, ios::binary);
    if (!encryptedInputFile) {
        cerr << "Error opening encrypted input file: " << encryptedFilePath << endl;
        return 1;
    }

    // Read encrypted data from file
    string encryptedData((istreambuf_iterator<char>(encryptedInputFile)), istreambuf_iterator<char>());
    encryptedInputFile.close();

    // Decrypt the data
    string decryptedData = DecryptData(encryptedData, key);

    // Open output file for decrypted data
    ofstream decryptedOutputFile(decryptedOutputFilePath, ios::binary);
    if (!decryptedOutputFile) {
        cerr << "Error opening output file for decrypted data: " << decryptedOutputFilePath << endl;
        return 1;
    }

    // Write decrypted data to output file
    decryptedOutputFile << decryptedData;
    decryptedOutputFile.close();

    cout << "Decryption completed. Decrypted data written to: " << decryptedOutputFilePath << endl;

    return 0;
}
