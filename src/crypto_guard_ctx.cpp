#include "crypto_guard_ctx.h"

#include <sstream>

#include <array>
#include <vector>

#include <openssl/evp.h>
#include <openssl/err.h>

namespace CryptoGuard
{
    class CryptoGuardCtx::Impl
    {
        friend CryptoGuardCtx;

        static const size_t BLOCK_SIZE = 32;    // Data block size
        static const size_t SHA256_SIZE = 32;   // SHA256 buffer length

        struct AesCipherParams
        {
            static const size_t KEY_SIZE = 32;              // AES-256 key size
            const EVP_CIPHER* cipher = EVP_aes_256_cbc();   // Cipher algorithm

            int encrypt;                              // 1 for encryption, 0 for decryption
            std::array<unsigned char, KEY_SIZE> key;  // Encryption key
            std::array<unsigned char, BLOCK_SIZE> iv; // Initialisation vector
        };

        AesCipherParams CreateCipherParamsFromPassword(std::string_view password);

        void ProcessFile(std::iostream& is, std::iostream& os, 
            std::string_view password, bool encrypt);

        static std::vector<unsigned char> ExtractAllData(std::iostream& is);

        template <typename S>
        static std::string ErrorText(S&& s);
        
        void EncryptFile(std::iostream& is, std::iostream& os, 
            std::string_view password);
        void DecryptFile(std::iostream& is, std::iostream& os, 
            std::string_view password);
        [[nodiscard]] std::string CalculateChecksum(std::iostream& is);

    public:
        Impl();
        ~Impl();
    };

    CryptoGuardCtx::Impl::AesCipherParams 
    CryptoGuardCtx::Impl::CreateCipherParamsFromPassword(std::string_view password)
    {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = 
            {'1', '2', '3', '4', '5', '6', '7', '8'};
        
        if (!EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(), 
            (unsigned char*)password.data(), password.size(), 1, 
            params.key.data(), params.iv.data()))
        {
            throw std::runtime_error(ErrorText("Failed to create "
                "a key from password"));
        }

        return params;
    }

    std::vector<unsigned char> 
    CryptoGuardCtx::Impl::ExtractAllData(std::iostream& is)
    {
        is.seekg(0); is.seekg(0, std::ios::end);
        size_t n_bytes = is.tellg();
        is.seekg(0);

        // The case of an empty file
        if (n_bytes == (size_t)-1) return {};
        
        std::vector<unsigned char> buffer(n_bytes);
        is.read((char*)buffer.data(), n_bytes);

        return buffer;
    }

    template <typename S>
    std::string CryptoGuardCtx::Impl::ErrorText(S&& s)
    {
        using namespace std::string_literals;

        std::string out(std::forward<S>(s));
        out += " (error code: "s;
        out += std::to_string(ERR_get_error());
        out += ")"s;

        return out;
    }

    void CryptoGuardCtx::Impl::ProcessFile(std::iostream& is, 
        std::iostream& os, 
        std::string_view password, 
        bool encrypt)
    {
        if (!is) throw std::runtime_error("Cannot open the input file");
        if (!os) throw std::runtime_error("Cannot generate the output file");
        if (&is == &os) throw std::logic_error("Input and output files cannot coincide"); 

        AesCipherParams params = CreateCipherParamsFromPassword(password);
        params.encrypt = encrypt ? 1 : 0;

        using pEvpCipher = std::unique_ptr<EVP_CIPHER_CTX, 
            decltype([](EVP_CIPHER_CTX* ctx)
                {
                    // Особый удалитель для контекста
                    EVP_CIPHER_CTX_free(ctx);
                })>;
        pEvpCipher ctx(EVP_CIPHER_CTX_new());

        if (!ctx.get())
        {
            throw std::runtime_error(ErrorText("Cannot create "
                "the ciphering context"));
        }
        
        // Инициализируем cipher
        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, 
            params.key.data(), params.iv.data(), params.encrypt))
        {
            throw std::runtime_error(ErrorText("Cannot initialise "
                "the ciphering context"));
        }

        std::array<unsigned char, BLOCK_SIZE> buffer_in;
        std::array<unsigned char, 
            BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH> buffer_out;
        int n_bytes_out;

        // Поблочное шифрование содержимого входящего потока
        while (true)
        {
            is.read(reinterpret_cast<char*>(buffer_in.data()), 
                BLOCK_SIZE);
            int n_bytes_in = is.gcount();
            
            if (!is && !is.eof())
            {
                throw std::runtime_error("Error reading from "
                    "the input file");
            }

            if (!n_bytes_in) break;

            if (!EVP_CipherUpdate(ctx.get(), 
                buffer_out.data(), &n_bytes_out, 
                buffer_in.data(), n_bytes_in))
            {
                throw std::runtime_error(ErrorText("Cannot update "
                    "the ciphering context"));
            }
            
            os.write(reinterpret_cast<char*>(buffer_out.data()), n_bytes_out);
            if (!os)
            {
                throw std::runtime_error("Error writing to "
                    "the output file");
            }
        }

        // Заканчиваем работу с cipher
        if (!EVP_CipherFinal_ex(ctx.get(), 
            buffer_out.data(), &n_bytes_out))
        {
            throw std::runtime_error(ErrorText("Cannot finalise "
                "the ciphering context"));
        }
        
        os.write(reinterpret_cast<char*>(buffer_out.data()), n_bytes_out);
        if (!os)
        {
            throw std::runtime_error("Error writing to "
                "the output file");
        }
    }

    CryptoGuardCtx::Impl::Impl()
    {
        OpenSSL_add_all_algorithms();
    }

    CryptoGuardCtx::Impl::~Impl()
    {
        EVP_cleanup();
    }

    void CryptoGuardCtx::Impl::EncryptFile(std::iostream& is, 
        std::iostream& os, 
        std::string_view password)
    {
        ProcessFile(is, os, password, true);
    }

    void CryptoGuardCtx::Impl::DecryptFile(std::iostream& is, 
        std::iostream& os, 
        std::string_view password)
    {
        ProcessFile(is, os, password, false);
    }

    std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream& is)
    {
        if (!is) throw std::runtime_error("Cannot open the input file");

        std::array<unsigned char, BLOCK_SIZE> buffer_in;
        std::array<unsigned char, SHA256_SIZE> sha256;

        // Подготовка обработчика
        using pEvpMD = std::unique_ptr<EVP_MD_CTX, 
            decltype([](EVP_MD_CTX* ctx)
                {
                    // Особый удалитель для контекста
                    EVP_MD_CTX_free(ctx);
                })>;
        pEvpMD ctx(EVP_MD_CTX_new());

        if (!ctx.get())
        {
            throw std::runtime_error(ErrorText("Cannot create "
                "the digesting context"));
        }
        
        // Инициализация
        if (!EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr))
        {
            throw std::runtime_error(ErrorText("Cannot initialise "
                "the digesting context"));
        }
        
        // Поблочное шифрование содержимого входящего потока
        while (true)
        {
            is.read(reinterpret_cast<char*>(buffer_in.data()), 
                BLOCK_SIZE);
            int n_bytes_in = is.gcount();
            
            if (!is && !is.eof())
            {
                throw std::runtime_error("Error reading from "
                    "the input file");
            }

            if (!n_bytes_in) break;

            if (!EVP_DigestUpdate(ctx.get(), buffer_in.data(), n_bytes_in))
            {
                throw std::runtime_error(ErrorText("Cannot update "
                    "the digesting context"));
            }
        }
        

        // Завершение
        if (!EVP_DigestFinal_ex(ctx.get(), sha256.data(), nullptr))
        {
            throw std::runtime_error(ErrorText("Cannot finalise "
                "the digesting context"));
        }
        
        std::ostringstream oss{};
        for (unsigned int v : sha256)
        {
            // Adding the leading zero (if needed).
            oss << (v < 0x10 ? "0" : "");
            oss << std::hex << v;
        }
        
        return oss.str();
    }

    CryptoGuardCtx::CryptoGuardCtx() : 
        p_impl_(std::make_unique<Impl>())
    {}

    CryptoGuardCtx::~CryptoGuardCtx() = default;

    CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx&&) noexcept = default;
    CryptoGuardCtx& CryptoGuardCtx::operator=(CryptoGuardCtx&&) noexcept = default;

    void CryptoGuardCtx::EncryptFile(std::iostream& is, 
        std::iostream& os, std::string_view password)
    {
        p_impl_->EncryptFile(is, os, password);
    }

    void CryptoGuardCtx::DecryptFile(std::iostream& is, 
        std::iostream& os, std::string_view password)
    {
        p_impl_->DecryptFile(is, os, password);
    }

    std::string CryptoGuardCtx::CalculateChecksum(std::iostream& is)
    {
        return p_impl_->CalculateChecksum(is);
    }
} // namespace CryptoGuard