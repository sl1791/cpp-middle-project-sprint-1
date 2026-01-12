#include "cmd_options.h"
#include <iostream>

namespace CryptoGuard
{
    std::string ProgramOptions::GetArg(const boost::program_options::variables_map& settings, 
        std::string_view field, 
        std::string_view msg) const
    {
        using namespace boost::program_options;
        using OptionPos = std::map<std::string, 
            boost::program_options::variable_value>::const_iterator;
        
        OptionPos pos = settings.find(field.data());
        if (pos == settings.end())
        {
            throw std::logic_error(msg.data());
        }

        return pos->second.as<std::string>();
    }

    ProgramOptions::ProgramOptions() : 
        desc_("Settings available")
    {
        using namespace boost::program_options;

        desc_.add_options()
            ("help,h", "list of all settings")
            ("command,c", value<std::string>(), "required action")
            ("input,i", value<std::string>(), "path to the input file")
            ("output,o", value<std::string>(), "path to the output file")
            ("password,p", value<std::string>(), "password for encoding/decoding");
    }

    ProgramOptions::~ProgramOptions() = default;

    void ProgramOptions::Parse(int argc, char* argv[], 
        std::ostream& os)
    {
        using namespace boost::program_options;

        variables_map settings;
        store(parse_command_line(argc, argv, desc_), settings);
        notify(settings);

        using OptionPos = std::map<std::string, 
            boost::program_options::variable_value>::const_iterator;
        OptionPos pos = settings.find("help");
        if (pos != settings.end())
        {
            os << desc_;
            return;
        }
        
        std::string command_str = GetArg(settings, "command", 
            "No command is provided");

        using CmdPos = std::unordered_map<std::string_view, 
            COMMAND_TYPE>::const_iterator;
        CmdPos cmd_pos = command_mapping_.find(command_str);
        if (cmd_pos != command_mapping_.end()) command_ = cmd_pos->second;
        // else is captured by the main part in switch
        
        input_file_ = GetArg(settings, "input", 
            "Input file is missing");

        switch (command_)
        {
        case COMMAND_TYPE::ENCRYPT:
        case COMMAND_TYPE::DECRYPT:
            output_file_ = GetArg(settings, "output", 
                "Output file is missing");
            password_ = GetArg(settings, "password", 
                "Password is missing");
            break;
        
        default:
            break;
        }
    }
}  // namespace CryptoGuard
