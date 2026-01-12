#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <algorithm>
#include <iostream>
#include <fstream>
#include <print>

#include <array>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>

int main(int argc, char* argv[])
{
    try
    {
        CryptoGuard::ProgramOptions options;
        CryptoGuard::CryptoGuardCtx crypto_ctx;

        options.Parse(argc, argv);

        std::fstream ifs(options.GetInputFile(), 
            std::ios::in | std::ios::binary);
        std::fstream ofs(options.GetOutputFile(), 
            std::ios::out | std::ios::binary);
        std::string password = options.GetPassword();

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand())
        {
        case COMMAND_TYPE::ENCRYPT:
            crypto_ctx.EncryptFile(ifs, ofs, password);
            std::print("File encrypted successfully!\n");
            break;

        case COMMAND_TYPE::DECRYPT:
            crypto_ctx.DecryptFile(ifs, ofs, password);
            std::print("File decrypted successfully!\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", 
                crypto_ctx.CalculateChecksum(ifs));
            break;

        default:
            throw std::runtime_error{"Unsupported command!"};
        }
    }
    catch (const std::exception& e)
    {
        std::print(std::cerr, "Error: {}\n", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}