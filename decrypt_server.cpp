#include <gmpxx.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdlib>
#include <unistd.h>         // close()
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>     // sockaddr_in, htons(), INADDR_ANY
#include <arpa/inet.h>      // inet_ntoa()
#include <map>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <openssl/rand.h>
#include <random>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <openssl/evp.h> // <-- Make sure this header is included
using namespace std;

/**
 * Derives a 256-bit AES key from the shared DH secret using SHA-256 KDF
 * Uses a fixed context string to prevent key reuse attacks
 */
// array<uint8_t, 32> deriveAesKey(const mpz_class &sharedSecret) {
//     // Convert shared secret to hex string for KDF input
//     string hexS = sharedSecret.get_str(16);
//     const string ctx = "DH-AES-Key-01";
//     string kdfInput = ctx + hexS;

//     array<uint8_t, 32> key{}; // Zero-initialize
//     SHA256_CTX shaCtx;
//     SHA256_Init(&shaCtx);
//     SHA256_Update(&shaCtx, reinterpret_cast<const uint8_t*>(kdfInput.data()), kdfInput.size());
//     SHA256_Final(key.data(), &shaCtx);

//     return key;
// }

array<uint8_t, 32> deriveAesKey(const mpz_class &sharedSecret) {
    // Convert shared secret to a hexadecimal string
    string hexS = sharedSecret.get_str(16);
    const string ctx = "DH-AES-Key-01";
    string kdfInput = ctx + hexS;

    array<uint8_t, 32> key{}; // Zero-initialize the key array
    
    // 1. Create a message digest context
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        throw runtime_error("EVP_MD_CTX_new() failed");
    }

    // 2. Initialize the digest operation with the SHA-256 algorithm
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("EVP_DigestInit_ex() failed");
    }

    // 3. Feed the input data to be hashed into the context
    if (1 != EVP_DigestUpdate(mdctx, kdfInput.c_str(), kdfInput.length())) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("EVP_DigestUpdate() failed");
    }

    // 4. Finalize the hash and retrieve the 32-byte digest
    unsigned int digest_len;
    if (1 != EVP_DigestFinal_ex(mdctx, key.data(), &digest_len)) {
        EVP_MD_CTX_free(mdctx);
        throw runtime_error("EVP_DigestFinal_ex() failed");
    }

    // 5. Clean up and free the context
    EVP_MD_CTX_free(mdctx);

    return key;
}
/**
 * Decrypt an AES-256-GCM encrypted packet
 * Input format: [12-byte IV][ciphertext][16-byte tag]
 * Returns decrypted plaintext as vector<char>
 */
vector<char> decrypt(const mpz_class &sharedSecret, const vector<char> &encrypted) {
    constexpr size_t ivLen = 12;
    constexpr size_t tagLen = 16;
    size_t totalLen = encrypted.size();

    // Enhanced input validation
    if (totalLen < ivLen + tagLen) {
        throw runtime_error("Packet too short for GCM");
    }

    // Parse packet components
    const uint8_t *data = reinterpret_cast<const uint8_t*>(encrypted.data());
    const uint8_t *iv = data;
    const uint8_t *cipher = data + ivLen;
    size_t cipherLen = totalLen - ivLen - tagLen;
    const uint8_t *tag = data + ivLen + cipherLen;

    // Additional validation for ciphertext length
    if (cipherLen == 0) {
        throw runtime_error("Empty ciphertext in GCM packet");
    }

    // Initialize OpenSSL GCM decrypt context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    // Set up AES-256-GCM decryption
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptInit_ex failed");
    }

    // Set IV length
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(ivLen), nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_CIPHER_CTX_ctrl (set IV length) failed");
    }

    // Set key and IV
    auto aesKey = deriveAesKey(sharedSecret);
    if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, aesKey.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptInit_ex (key and IV) failed");
    }

    // Allocate plaintext buffer with extra space for potential padding
    vector<char> plaintext(cipherLen + 16);  // Extra space for safety
    int outLen = 0;
    int totalOutLen = 0;

    // Perform decryption
    if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<uint8_t*>(plaintext.data()), &outLen, cipher, static_cast<int>(cipherLen))) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptUpdate failed");
    }
    totalOutLen += outLen;

    // Set expected tag and verify
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tagLen), const_cast<uint8_t*>(tag))) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_CIPHER_CTX_ctrl (set tag) failed");
    }

    // Finalize decryption and get any remaining bytes
    int ret = EVP_DecryptFinal_ex(ctx, reinterpret_cast<uint8_t*>(plaintext.data()) + totalOutLen, &outLen);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        throw runtime_error("Decryption failed: tag mismatch");
    }
    totalOutLen += outLen;

    // Resize to actual decrypted length
    plaintext.resize(totalOutLen);
    return plaintext;
}


/**
 * Receive size-prefixed binary data over TCP connection
 * Protocol: [4-byte size in network order][data]
 */
void recv_key(int sockfd, vector<uint8_t>& data) {
    // Receive data size first
    uint32_t data_size = 0;
    ssize_t bytes_received = recv(sockfd, &data_size, sizeof(data_size), MSG_WAITALL);
    if (bytes_received != sizeof(data_size)) {
        perror("[-] Error receiving data size over TCP");
        exit(EXIT_FAILURE);
    }

    // Convert from network byte order
    data_size = ntohl(data_size);
    cout << "[+] TCP: Expected to receive " << data_size << " bytes of key data" << endl;

    // Receive actual data
    data.resize(data_size);
    bytes_received = recv(sockfd, data.data(), data_size, MSG_WAITALL);
    if (bytes_received != static_cast<ssize_t>(data_size)) {
        perror("[-] Error receiving key data over TCP");
        exit(EXIT_FAILURE);
    }

    cout << "[+] TCP: Successfully received " << bytes_received << " bytes of key data" << endl;
}

/**
 * Send size-prefixed binary data over TCP connection
 * Protocol: [4-byte size in network order][data]
 */
void send_key(int sockfd, const vector<uint8_t>& data) {
    // Send data size first
    uint32_t data_size = static_cast<uint32_t>(data.size());
    uint32_t network_size = htonl(data_size);

    ssize_t bytes_sent = send(sockfd, &network_size, sizeof(network_size), 0);
    if (bytes_sent != sizeof(network_size)) {
        perror("[-] Error sending data size over TCP");
        exit(EXIT_FAILURE);
    }

    cout << "[+] TCP: Sending " << data_size << " bytes of key data" << endl;

    // Send actual data
    bytes_sent = send(sockfd, data.data(), data_size, 0);
    if (bytes_sent != static_cast<ssize_t>(data_size)) {
        perror("[-] Error sending key data over TCP");
        exit(EXIT_FAILURE);
    }

    cout << "[+] TCP: Successfully sent " << bytes_sent << " bytes of key data" << endl;
}

/**
 * Generate a cryptographically secure probable prime of approximately 256 bits
 * Uses OpenSSL CSPRNG and GMP's prime generation
 */
mpz_class prime_gen() {
    vector<unsigned char> buf(32); // 32 bytes = 256 bits
    if (RAND_bytes(buf.data(), buf.size()) != 1) {
        throw runtime_error("CSPRNG failure");
    }

    // Build candidate number from random bytes
    mpz_class candidate = 0;
    for (auto byte : buf) {
        candidate <<= 8;
        candidate += byte;
    }

    // Force highest bit set (ensures 256-bit length) and make odd
    mpz_setbit(candidate.get_mpz_t(), 255);
    mpz_setbit(candidate.get_mpz_t(), 0);

    // Find next probable prime
    mpz_class prime;
    mpz_nextprime(prime.get_mpz_t(), candidate.get_mpz_t());
    return prime;
}

/**
 * Modular exponentiation: computes (base^exp) mod mod efficiently
 * Uses GMP's optimized modular exponentiation
 */
mpz_class power(const mpz_class &base, const mpz_class &exp, const mpz_class &mod) {
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return result;
}

/**
 * Convert mpz_class to minimal binary representation
 * Returns only the necessary bytes (no padding)
 */
vector<uint8_t> mpz_to_binary(const mpz_class& num) {
    // Calculate minimum bytes needed
    size_t size_needed = (mpz_sizeinbase(num.get_mpz_t(), 2) + 7) / 8;
    if (size_needed == 0) size_needed = 1; // Handle zero case

    vector<uint8_t> result(size_needed);
    size_t count = 0;

    mpz_export(result.data(), &count, 1, 1, 0, 0, num.get_mpz_t());
    
    // Resize to actual bytes used
    if (count > 0 && count != size_needed) {
        result.resize(count);
    }

    return result;
}

/**
 * Convert binary data back to mpz_class
 * Handles empty input gracefully
 */
mpz_class binary_to_mpz(const vector<uint8_t>& data) {
    if (data.empty()) {
        return mpz_class(0);
    }

    mpz_class result;
    mpz_import(result.get_mpz_t(), data.size(), 1, 1, 0, 0, data.data());
    return result;
}

/**
 * Server-side Diffie-Hellman key exchange over TCP
 * Receives P, G, A from client and sends back B
 * Returns the computed shared secret
 */
mpz_class server_key(int sockfd) {
    cout << "\n=== SERVER KEY EXCHANGE ===" << endl;

    // Receive DH parameters P and G from client
    vector<uint8_t> P_binary, G_binary;
    recv_key(sockfd, P_binary);
    recv_key(sockfd, G_binary);

    mpz_class P = binary_to_mpz(P_binary);
    mpz_class G = binary_to_mpz(G_binary);

    //cout << "SERVER - P (received): " << P << endl;
    //cout << "SERVER - G (received): " << G << endl;

    // Receive client's public key A
    vector<uint8_t> A_binary;
    recv_key(sockfd, A_binary);
    mpz_class A = binary_to_mpz(A_binary);

    //cout << "SERVER - A (received): " << A << endl;

    // Generate server's private key and compute public key B = G^b mod P
    mpz_class b = prime_gen();
    mpz_class B = power(G, b, P);

    //cout << "SERVER - B (public): " << B << endl;

    // Send server's public key to client
    send_key(sockfd, mpz_to_binary(B));

    // Compute shared secret: shared = A^b mod P
    mpz_class shared = power(A, b, P);
    //cout << "SERVER - Shared key: " << shared << endl;

    return shared;
}
