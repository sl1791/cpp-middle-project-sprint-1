#include "crypto_guard_ctx.h"
#include <openssl/evp.h>
#include <array>

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

    static AesCipherParams CreateChiperParamsFromPassword(std::string_view password);
};

CryptoGuardCtx::Impl::Impl() : chiper(EVP_CIPHER_CTX_new())
{ }

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{

}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password)
{

}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream)
{
    return "NOT_IMPLEMENTED"; 
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

CryptoGuardCtx::CryptoGuardCtx() = default;
CryptoGuardCtx::~CryptoGuardCtx() = default;

}  // namespace CryptoGuard
