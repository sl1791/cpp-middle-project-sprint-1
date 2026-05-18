#include "crypto_guard_ctx.h"
#include <openssl/evp.h>
#include <array>
#include <vector>
#include <iostream>

namespace CryptoGuard {

auto evp_deleter = [](EVP_CIPHER_CTX* ptr) { EVP_CIPHER_CTX_free(ptr); };
using ciperUPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(evp_deleter)>;

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

////////////////////////////////////////////////////////////////////////
class CryptoGuardCtx::Impl
{
public:
    Impl();
    ~Impl() = default;
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);
private:
    ciperUPtr chiper;

    void MakeOperation(std::iostream &inStream, std::iostream &outStream, const char* error);
    static AesCipherParams CreateChiperParamsFromPassword(std::string_view password);
};

CryptoGuardCtx::Impl::Impl() : chiper(EVP_CIPHER_CTX_new())
{ }

void CryptoGuardCtx::Impl::MakeOperation(std::iostream &inStream, 
    std::iostream &outStream, const char* error)
{
    const size_t BLOCK_SIZE = 16;
    std::vector<unsigned char> outBuf(BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(BLOCK_SIZE);
    int outLen = 0;

    while(inStream.read(reinterpret_cast<char*>(inBuf.data()), BLOCK_SIZE))
    {
        if (!EVP_CipherUpdate(chiper.get(), outBuf.data(), &outLen, 
                inBuf.data(), BLOCK_SIZE)) 
            throw std::runtime_error{std::format("{} : {}", error, __LINE__)};
        outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
    }

    if (inStream.gcount() > 0) 
    {
        size_t last_block_size = inStream.gcount();
        if (!EVP_CipherUpdate(chiper.get(), outBuf.data(), &outLen, 
                inBuf.data(), static_cast<int>(last_block_size))) 
            throw std::runtime_error{std::format("{} : {}", error, __LINE__)};
        outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);
    }

    // Заканчиваем работу с cipher
    if (!EVP_CipherFinal_ex(chiper.get(), outBuf.data(), &outLen)) 
        throw std::runtime_error{std::format("{} : {}", error, __LINE__)};
    
    outStream.write(reinterpret_cast<char*>(outBuf.data()), outLen);

    if(!outStream)
        throw std::runtime_error{std::format("{} : {}", error, __LINE__)};
}

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, 
    std::iostream &outStream, std::string_view password)
{
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 1;

    const char* err = "Encryption failed.";

    // Инициализируем cipher
    if (!EVP_CipherInit_ex(chiper.get(), params.cipher, nullptr, 
                params.key.data(), params.iv.data(), params.encrypt)) 
        throw std::runtime_error{std::format("{} : {}", err, __LINE__)};

    try
    {
        MakeOperation(inStream, outStream, err);
    }
    catch(...)
    {
        // помню о ScopeGuard.
        // нет времени сделать красиво.
        EVP_CIPHER_CTX_reset(chiper.get());
        throw;
    }
    EVP_CIPHER_CTX_reset(chiper.get());
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = 0;  // 0 для дешифрования

    const char* err = "Decryption failed.";
    // Инициализируем cipher для дешифрования
    if (!EVP_CipherInit_ex(chiper.get(), params.cipher, nullptr, 
                params.key.data(), params.iv.data(), params.encrypt)) 
        throw std::runtime_error{err};

    try
    {
        MakeOperation(inStream, outStream, err);
    }
    catch(...)
    {
        EVP_CIPHER_CTX_reset(chiper.get());
        throw;
    }
    EVP_CIPHER_CTX_reset(chiper.get());
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream)
{
    const char* error = "Failed to calculate checksum.";
    
    auto md_deleter = [](EVP_MD_CTX* ptr) { EVP_MD_CTX_free(ptr); };
    std::unique_ptr<EVP_MD_CTX, decltype(md_deleter)> ctx(EVP_MD_CTX_new(), md_deleter);
    if (!ctx)
        throw std::runtime_error{std::format("{} : {}", error, __LINE__)};
    
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) 
        throw std::runtime_error{std::format("{} : {}", error, __LINE__)};

    const size_t BUFFER_SIZE = 8192;  // 8KB buffer for efficient reading
    std::vector<unsigned char> buffer(BUFFER_SIZE);
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hash_len = 0;
        
    while (inStream.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE) || 
           inStream.gcount() > 0) {
        size_t bytes_read = inStream.gcount();
        if (EVP_DigestUpdate(ctx.get(), buffer.data(), bytes_read) != 1) 
            throw std::runtime_error{std::format("{} : {}", error, __LINE__)};
    }
    
    // Finalize hash calculation
    if (EVP_DigestFinal_ex(ctx.get(), hash.data(), &hash_len) != 1)
        throw std::runtime_error{std::format("{} : {}", error, __LINE__)};
    
    // Convert hash to hexadecimal string
    std::string result;
    result.reserve(hash_len * 2);
    for (unsigned int i = 0; i < hash_len; ++i) 
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", hash[i]);
        result += hex;
    }
    
    return result;
}

AesCipherParams 
CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password) 
{
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
            reinterpret_cast<const unsigned char *>(password.data()), 
            password.size(), 1,
            params.key.data(), params.iv.data());

    if (result == 0) {
        throw std::runtime_error{"Failed to create a key from password"};
    }

    return params;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void CryptoGuardCtx::EncryptFile(std::iostream &inStream, 
    std::iostream &outStream, std::string_view password)
{
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, 
    std::iostream &outStream, std::string_view password)
{
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) 
{ 
    return pImpl_->CalculateChecksum(inStream);
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>())
{ }
CryptoGuardCtx::~CryptoGuardCtx() = default;

}  // namespace CryptoGuard
