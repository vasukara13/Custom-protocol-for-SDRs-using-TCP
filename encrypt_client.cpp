#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include <gmpxx.h>

using namespace std;

// TCP version of recv_key - receives binary key data over TCP connection
void recv_key(int sockfd, vector<uint8_t>& data) {
    // First, receive the size of the incoming data
    uint32_t data_size;
    ssize_t bytes_received = recv(sockfd, &data_size, sizeof(data_size), MSG_WAITALL);
    if (bytes_received < 0) {
        perror("[-] Error receiving data size over TCP");
        exit(1);
    }
    if (bytes_received != sizeof(data_size)) {
        cerr << "[-] Incomplete data size received over TCP" << endl;
        exit(1);
    }
    
    // Convert from network byte order to host byte order
    data_size = ntohl(data_size);
    
    cout << "[+] TCP: Expected to receive " << data_size << " bytes of key data" << endl;
    
    // Resize vector to accommodate the incoming data
    data.resize(data_size);
    
    // Receive the actual key data
    bytes_received = recv(sockfd, data.data(), data_size, MSG_WAITALL);
    if (bytes_received < 0) {
        perror("[-] Error receiving key data over TCP");
        exit(1);
    }
    if (bytes_received != (ssize_t)data_size) {
        cerr << "[-] Incomplete key data received over TCP. Expected: " 
             << data_size << " bytes, Got: " << bytes_received << " bytes" << endl;
        exit(1);
    }
    
    cout << "[+] TCP: Successfully received " << bytes_received << " bytes of key data" << endl;
}

// TCP version of send_key - sends binary key data over TCP connection
void send_key(int sockfd, const vector<uint8_t>& data) {
    // First, send the size of the data
    uint32_t data_size = data.size();
    uint32_t network_size = htonl(data_size);  // Convert to network byte order
    
    ssize_t bytes_sent = send(sockfd, &network_size, sizeof(network_size), 0);
    if (bytes_sent < 0) {
        perror("[-] Error sending data size over TCP");
        exit(1);
    }
    if (bytes_sent != sizeof(network_size)) {
        cerr << "[-] Incomplete data size sent over TCP" << endl;
        exit(1);
    }
    
    cout << "[+] TCP: Sending " << data_size << " bytes of key data" << endl;
    
    // Send the actual key data
    bytes_sent = send(sockfd, data.data(), data_size, 0);
    if (bytes_sent < 0) {
        perror("[-] Error sending key data over TCP");
        exit(1);
    }
    if (bytes_sent != (ssize_t)data_size) {
        cerr << "[-] Incomplete key data sent over TCP. Expected: " 
             << data_size << " bytes, Sent: " << bytes_sent << " bytes" << endl;
        exit(1);
    }
    
    cout << "[+] TCP: Successfully sent " << bytes_sent << " bytes of key data" << endl;
}



// array<uint8_t, 32> deriveAesKey(const mpz_class &sharedSecret) {
//     string hexS = sharedSecret.get_str(16);
//     const string ctx = "DH-AES-Key-01";
//     string kdfInput = ctx + hexS;
    
//     array<uint8_t, 32> key;
//     SHA256_CTX shaCtx;
//     SHA256_Init(&shaCtx);
//     SHA256_Update(&shaCtx, reinterpret_cast<const uint8_t*>(kdfInput.data()), kdfInput.size());
//     SHA256_Final(key.data(), &shaCtx);
    
//     return key;
// }

#include <openssl/evp.h> // Make sure you have this include for EVP functions


array<uint8_t, 32> deriveAesKey(const mpz_class &sharedSecret) {
    // Convert shared secret to a hexadecimal string
    std::string hexS = sharedSecret.get_str(16);
    const std::string ctx = "DH-AES-Key-01";
    std::string kdfInput = ctx + hexS;

    std::array<uint8_t, 32> key{}; // Zero-initialize the key array
    
    // 1. Create a message digest context
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        throw std::runtime_error("EVP_MD_CTX_new() failed");
    }

    // 2. Initialize the digest operation with the SHA-256 algorithm
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex() failed");
    }

    // 3. Feed the input data to be hashed into the context
    if (1 != EVP_DigestUpdate(mdctx, kdfInput.c_str(), kdfInput.length())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate() failed");
    }

    // 4. Finalize the hash and retrieve the 32-byte digest
    unsigned int digest_len;
    if (1 != EVP_DigestFinal_ex(mdctx, key.data(), &digest_len)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex() failed");
    }

    // 5. Clean up and free the context
    EVP_MD_CTX_free(mdctx);

    return key;
}

// ... other includes and functions ...
vector<char> encrypt(const mpz_class& shared, const vector<char>& plaintext) {
    // 1. Derive AES key
    auto aesKey = deriveAesKey(shared);

    const uint8_t* inData = reinterpret_cast<const uint8_t*>(plaintext.data());
    size_t inLen = plaintext.size();

    // 2. Generate a unique, random 12-byte IV
    uint8_t iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        throw runtime_error("Failed to generate random IV");
    }

    // 3. Initialize OpenSSL context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw runtime_error("Failed to create EVP_CIPHER_CTX");

    // 4. Setup cipher (AES-256-GCM) and set IV length
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);

    // 5. Set key and IV
    EVP_EncryptInit_ex(ctx, NULL, NULL, aesKey.data(), iv);

    // 6. Encrypt plaintext
    vector<uint8_t> ciphertext(inLen);
    int outLen = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen, inData, inLen);

    // 7. Finalize encryption
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &outLen);

    // 8. Get the 16-byte authentication tag
    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
    EVP_CIPHER_CTX_free(ctx);

    // 9. Assemble the final packet: [IV] || [Ciphertext] || [Tag]
    vector<char> packet;
    packet.reserve(sizeof(iv) + ciphertext.size() + sizeof(tag));
    
    // Insert IV
    packet.insert(packet.end(), reinterpret_cast<char*>(iv), reinterpret_cast<char*>(iv) + sizeof(iv));
    // Insert Ciphertext
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());
    // Insert Tag
    packet.insert(packet.end(), reinterpret_cast<char*>(tag), reinterpret_cast<char*>(tag) + sizeof(tag));

    return packet;
}
// string encrypt(const mpz_class& shared, const string& plaintext) {
//     // 1. Derive the AES key from the shared secret
//     auto aesKey = deriveAesKey(shared);

//     const uint8_t* inData = reinterpret_cast<const uint8_t*>(plaintext.data());
//     size_t inLen = plaintext.size();

//     // 2. Generate a unique, random 12-byte IV for each encryption
//     uint8_t iv[12];
//     if (RAND_bytes(iv, sizeof(iv)) != 1) {
//         throw runtime_error("Failed to generate random IV");
//     }

//     // 3. Initialize the OpenSSL context for encryption
//     EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//     if (!ctx) {
//         throw runtime_error("Failed to create EVP_CIPHER_CTX");
//     }

//     // 4. Set up the cipher type (AES-256-GCM)
//     if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
//         EVP_CIPHER_CTX_free(ctx);
//         throw runtime_error("EVP_EncryptInit_ex (cipher setup) failed");
//     }

//     // 5. Set the IV length
//     if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL)) {
//         EVP_CIPHER_CTX_free(ctx);
//         throw runtime_error("EVP_CIPHER_CTX_ctrl (set IV length) failed");
//     }

//     // 6. Set the key and IV
//     if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, aesKey.data(), iv)) {
//         EVP_CIPHER_CTX_free(ctx);
//         throw runtime_error("EVP_EncryptInit_ex (key and IV) failed");
//     }

//     // 7. Encrypt the plaintext
//     // GCM doesn't use padding, so the ciphertext will be the same size as the plaintext.
//     vector<uint8_t> cipher(inLen);
//     int outLen = 0;
//     if (1 != EVP_EncryptUpdate(ctx, cipher.data(), &outLen, inData, inLen)) {
//         EVP_CIPHER_CTX_free(ctx);
//         throw runtime_error("EVP_EncryptUpdate failed");
//     }

//     // 8. Finalize the encryption. This step is crucial.
//     // Provide a valid buffer (even if no output is expected) and check the return code.
//     if (1 != EVP_EncryptFinal_ex(ctx, cipher.data() + outLen, &outLen)) {
//         EVP_CIPHER_CTX_free(ctx);
//         throw runtime_error("EVP_EncryptFinal_ex failed");
//     }

//     // 9. Get the 16-byte authentication tag. This can only be done AFTER finalization.
//     uint8_t tag[16];
//     if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag)) {
//         EVP_CIPHER_CTX_free(ctx);
//         throw runtime_error("EVP_CIPHER_CTX_ctrl (get tag) failed");
//     }

//     // 10. Clean up the context
//     EVP_CIPHER_CTX_free(ctx);

//     // 11. Assemble the final packet: [12-byte IV] || [Ciphertext] || [16-byte Tag]
//     string packet;
//     packet.reserve(sizeof(iv) + cipher.size() + sizeof(tag));
//     packet.append(reinterpret_cast<const char*>(iv), sizeof(iv));
//     packet.append(reinterpret_cast<const char*>(cipher.data()), cipher.size());
//     packet.append(reinterpret_cast<const char*>(tag), sizeof(tag));

//     return packet;
// }


// 📦 Output Size Breakdown:
// Component	Size (bytes)	Notes
// IV	12	96-bit random initialization vector
// Ciphertext	500	Same size as plaintext (AES-GCM has no padding)
// Auth Tag	16	Default tag size in GCM mode
// Total	528	= 12 + 500 + 16

// ===== UTILITY FUNCTIONS =====
mpz_class prime_gen() {
    vector<unsigned char> buf(32);  // 32 bytes = 256 bits
    if (RAND_bytes(buf.data(), buf.size()) != 1) {
        throw runtime_error("CSPRNG failure");
    }

    mpz_class candidate = 0;
    for (auto byte : buf) {
        candidate <<= 8;
        candidate += byte;
    }

    // Force full 256 bits and make it odd
    mpz_setbit(candidate.get_mpz_t(), 255);
    mpz_setbit(candidate.get_mpz_t(), 0);

    mpz_class prime;
    mpz_nextprime(prime.get_mpz_t(), candidate.get_mpz_t());
    return prime;
}

mpz_class power(const mpz_class &base, const mpz_class &exp, const mpz_class &mod) {
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}

vector<uint8_t> mpz_to_binary(const mpz_class& num) {
    // First, get the actual size needed
    size_t size_needed = (mpz_sizeinbase(num.get_mpz_t(), 2) + 7) / 8;
    if (size_needed == 0) size_needed = 1; // Handle zero case
    
    vector<uint8_t> result(size_needed);
    size_t count = 0;
    
    mpz_export(result.data(), &count, 1, 1, 0, 0, num.get_mpz_t());
    
    // Resize to actual bytes used
    if (count > 0) {
        result.resize(count);
    }
    
    cout << "[DEBUG] mpz_to_binary: number " << num << " -> " << result.size() << " bytes" << endl;
    return result;
}

mpz_class binary_to_mpz(const vector<uint8_t>& data) {
    if (data.empty()) {
        return mpz_class(0);
    }
    
    mpz_class result;
    mpz_import(result.get_mpz_t(), data.size(), 1, 1, 0, 0, data.data());
    
    cout << "[DEBUG] binary_to_mpz: " << data.size() << " bytes -> number " << result << endl;
    return result;
}
// ===== KEY EXCHANGE FUNCTIONS =====
mpz_class client_key(int sockfd) {
    cout << "\n=== CLIENT KEY EXCHANGE ===" << endl;
    
    // Generate P, G
    mpz_class P = prime_gen();
    mpz_class G = 2;
    
    cout << "CLIENT - P: " << P << endl;
    cout << "CLIENT - G: " << G << endl;
    
    // Send P, G
    send_key(sockfd, mpz_to_binary(P));
    send_key(sockfd, mpz_to_binary(G));
    
    // Generate client's keys
    mpz_class a = prime_gen();
    mpz_class A = power(G, a, P);
    
    cout << "CLIENT - A (public): " << A << endl;
    
    // Send A
    send_key(sockfd, mpz_to_binary(A));
    
    // Receive B
    vector<uint8_t> B_binary;
    recv_key(sockfd, B_binary);
    mpz_class B = binary_to_mpz(B_binary);
    
    cout << "CLIENT - B (received): " << B << endl;
    
    // Compute shared secret
    mpz_class shared = power(B, a, P);
    cout << "CLIENT - Shared key: " << shared << endl;
    
    return shared;
}






// You do NOT directly use this 2048-bit value as an AES key.

// Why?

// AES requires exactly 128, 192, or 256 bits (16, 24, or 32 bytes).

// Using the raw DH output can be dangerous (might have structure, not uniformly random).

// You want a clean, uniform key.

//https://chatgpt.com/share/68865bb2-30b8-8006-83ed-95c2ce6eed4f