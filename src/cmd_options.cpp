#include "cmd_options.h"
#include <iostream>
#include <print>


namespace po = boost::program_options;
namespace CryptoGuard {

/*Options*/
static const char* s_HelpOp = "help";
static const char* s_CmdOp = "command";
static const char* s_InputOp = "input";
static const char* s_OutputOp = "output";
static const char* s_PasswordOp = "password";

/*Commands*/
static const char* s_EncryptCmd = "encrypt";
static const char* s_DecryptCmd = "decrypt";
static const char* s_ChecksumCmd = "checksum";

ProgramOptions::ProgramOptions() : desc_("Allowed options") 
{ 
    auto fn = [&](const std::string& value)
    {
        auto it = commandMapping_.find(value);
        if (it == commandMapping_.end()) 
            throw std::runtime_error{"Unsupported command"};
        command_ = it->second;
    };

    desc_.add_options()
    (s_HelpOp, "produce help message")
    (s_CmdOp, po::value<std::string>()->notifier(fn), "values: encrypt decrypt checksum")
    (s_InputOp, po::value<std::string>(&inputFile_), "путь до входного файла")
    (s_OutputOp, po::value<std::string>(&outputFile_), "путь до файла, в котором будет сохранён результат")
    (s_PasswordOp, po::value<std::string>(&password_)/*->required()*/, "пароль для шифрования и дешифрования");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) 
{
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm); 

    if(vm.count(s_HelpOp))
        std::cout << desc_ << "\n";

    bool showHelp = 
                inputFile_.empty() ||
                outputFile_.empty() ||
                password_.empty();

    if(showHelp)
        throw std::runtime_error{"Unsupported command"};
}

}  // namespace CryptoGuard
