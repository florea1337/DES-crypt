#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/des.h>
#include <cryptopp/modes.h>
#include <cryptopp/base64.h>

using namespace CryptoPP;
using namespace std;

// Function to perform DES encryption with CBC mode and PKCS7 padding
string EncryptData(const string& inputData, const string& key) {
    byte iv[DES::BLOCKSIZE] = { 0 }; // Initialization Vector

    // Prepare key and IV
    SecByteBlock byteKey((const byte*)key.data(), DES::DEFAULT_KEYLENGTH);

    // Encryptor setup
    CBC_Mode<DES>::Encryption encryptor;
    encryptor.SetKeyWithIV(byteKey, byteKey.size(), iv);

    // Encrypt data
    string encryptedData;
    StringSource(inputData, true,
        new StreamTransformationFilter(encryptor,
            new Base64Encoder(
                new StringSink(encryptedData),
                false // Do not append line breaks
            )
        )
    );

    return encryptedData;
}

int main() {
    // File paths
    string inputFilePath = "input.txt"; // Adjust path as needed
    string outputFilePath = "output.txt"; // Adjust path as needed
    string key = "56410841"; // Encryption key

    // Open input file
    ifstream inputFile(inputFilePath, ios::binary);
    if (!inputFile) {
        cerr << "Error opening input file: " << inputFilePath << endl;
        return 1;
    }

    // Read input data from file
    string inputData((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
    inputFile.close();

    // Encrypt the data
    string encryptedData = EncryptData(inputData, key);

    // Open output file
    ofstream outputFile(outputFilePath, ios::binary);
    if (!outputFile) {
        cerr << "Error opening output file: " << outputFilePath << endl;
        return 1;
    }

    // Write encrypted data to output file
    outputFile << encryptedData;
    outputFile.close();

    cout << "Encryption completed. Encrypted data written to: " << outputFilePath << endl;

    return 0;
}
