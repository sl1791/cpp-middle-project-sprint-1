#pragma once

#include <boost/program_options.hpp>
#include <iostream>
#include <string>
#include <unordered_map>

namespace CryptoGuard
{
    class ProgramOptions
    {
    public:
        enum class COMMAND_TYPE
        {
            ENCRYPT,
            DECRYPT,
            CHECKSUM
        };
        
    private:
        COMMAND_TYPE command_;
        const std::unordered_map<std::string_view, COMMAND_TYPE> command_mapping_ =
        {
            {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
            {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
            {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
        };

        std::string input_file_;
        std::string output_file_;
        std::string password_;

        boost::program_options::options_description desc_;

        std::string GetArg(const boost::program_options::variables_map& settings, 
            std::string_view field,
            std::string_view msg) const;

    public:
        ProgramOptions();
        ~ProgramOptions();

        void Parse(int argc, char* argv[], 
            std::ostream& os = std::cout);

        COMMAND_TYPE GetCommand() const { return command_; }
        std::string GetInputFile() const { return input_file_; }
        std::string GetOutputFile() const { return output_file_; }
        std::string GetPassword() const { return password_; }
    };
} // namespace CryptoGuard