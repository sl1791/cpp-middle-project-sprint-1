#pragma once

#include <iostream>
#include <string>
#include <memory>
#include <experimental/propagate_const>

namespace CryptoGuard
{
    class CryptoGuardCtx
    {
    private:
        class Impl;
        std::experimental::propagate_const<std::unique_ptr<Impl>> p_impl_;

    public:
        CryptoGuardCtx();
        ~CryptoGuardCtx();

        CryptoGuardCtx(const CryptoGuardCtx&) = delete;
        CryptoGuardCtx& operator=(const CryptoGuardCtx&) = delete;

        CryptoGuardCtx(CryptoGuardCtx&&) noexcept;
        CryptoGuardCtx& operator=(CryptoGuardCtx&&) noexcept;

        // API
        void EncryptFile(std::iostream& is, std::iostream& os, 
            std::string_view password);
        
        void DecryptFile(std::iostream& is, std::iostream& os, 
            std::string_view password);
        
        std::string CalculateChecksum(std::iostream& is);
    };
}  // namespace CryptoGuard
