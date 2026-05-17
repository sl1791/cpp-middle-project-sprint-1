#include <gtest/gtest.h>
#include <cmd_options.h>

#define INPUTFILE "input.txt"
#define OUTPUTFILE "output.txt"
#define PASSWORD "sinecura"

TEST(ProgramOptions, Help)
{ 
    char str1[] = "--help";

    char* val_array[] = {str1, str1};
    CryptoGuard::ProgramOptions options;
    options.Parse(std::size(val_array), val_array);
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::HELP);
} 

TEST(ProgramOptions, Encrypt)
{ 
    char str1[] = "--command=encrypt";
    char str2[] = "--input=" INPUTFILE;
    char str3[] = "--output=" OUTPUTFILE;
    char str4[] = "--password=" PASSWORD;
    char* val_array[] = {str1, str1, str2, str3, str4};

    CryptoGuard::ProgramOptions options;
    options.Parse(std::size(val_array), val_array);
    
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), INPUTFILE);
    EXPECT_EQ(options.GetOutputFile(), OUTPUTFILE);
    EXPECT_EQ(options.GetPassword(), PASSWORD);
} 

TEST(ProgramOptions, Decrypt)
{ 
    char str1[] = "--command=decrypt";
    char str2[] = "--input=" INPUTFILE;
    char str3[] = "--output=" OUTPUTFILE;
    char str4[] = "--password=" PASSWORD;
    char* val_array[] = { str1, str1, str2, str3, str4};

    CryptoGuard::ProgramOptions options;
    options.Parse(std::size(val_array), val_array);
   
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), INPUTFILE);
    EXPECT_EQ(options.GetOutputFile(), OUTPUTFILE);
    EXPECT_EQ(options.GetPassword(), PASSWORD);
} 

TEST(ProgramOptions, Checksum)
{ 
    char str1[] = "--command=checksum";
    char str2[] = "--input=" INPUTFILE;
    char str3[] = "--output=" OUTPUTFILE;
    char* val_array[] = {str1, str1, str2, str3};

    CryptoGuard::ProgramOptions options;
    options.Parse(std::size(val_array), val_array);
    
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), INPUTFILE);
    EXPECT_EQ(options.GetOutputFile(), OUTPUTFILE);
} 

TEST(ProgramOptions, Error1)
{ 
    char str1[] = "--command=XXX";
    char str2[] = "--input=" INPUTFILE;
    char str3[] = "--output=" OUTPUTFILE;
    char str4[] = "--password=" PASSWORD;
    char* val_array[] = {str1, str1, str2, str3, str4};

    CryptoGuard::ProgramOptions options;
    options.Parse(std::size(val_array), val_array);
    
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ERROR);
    EXPECT_EQ(options.GetInputFile(), INPUTFILE);
    EXPECT_EQ(options.GetOutputFile(), OUTPUTFILE);
    EXPECT_EQ(options.GetPassword(), PASSWORD);
} 

TEST(ProgramOptions, Error2)
{ 
    char str1[] = "--command=encrypt";
    char str2[] = "--input=" INPUTFILE;
    char str3[] = "--output=" OUTPUTFILE;
    char* val_array[] = {str1, str1, str2, str3};

    CryptoGuard::ProgramOptions options;
    options.Parse(std::size(val_array), val_array);
    
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ERROR);
    EXPECT_EQ(options.GetInputFile(), INPUTFILE);
    EXPECT_EQ(options.GetOutputFile(), OUTPUTFILE);
    EXPECT_EQ(options.GetPassword(), "");
} 
