/* Copyright (C) 2011-2025 Codership Oy <info@codership.com> */

#ifndef _GARB_CONFIG_HPP_
#define _GARB_CONFIG_HPP_

#include <string>
#include <iostream>

namespace garb
{

class Config
{
public:
    class Exit{}; // thrown by ctor to signal exit on --help and --version

    static std::string const DEFAULT_SST; // default (empty) SST request

    Config (int argc, char* argv[]);
    ~Config () {}

    bool               daemon()  const { return daemon_ ; }
    const std::string& name()    const { return name_   ; }
    const std::string& address() const { return address_; }
    const std::string& group()   const { return group_  ; }
    const std::string& sst()     const { return sst_    ; }
    const std::string& donor()   const { return donor_  ; }
    const std::string& options() const { return options_; }
    const std::string& cfg()     const { return cfg_    ; }
    const std::string& log()     const { return log_    ; }
    const std::string& workdir() const { return workdir_; }
<<<<<<< HEAD
    bool  extended_exit_codes() const { return extended_exit_codes_; }
#if defined(WITH_COREDUMPER) && WITH_COREDUMPER
    const std::string& coredumper() const { return coredumper_; }
#endif
    bool               exit()    const { return exit_   ; }
    const std::string& recv_script() const { return recv_script_    ; }
    bool               wait_for_recv_script_exit() const { return wait_for_recv_script_exit_; }
    const std::string& post_recv_script() const { return post_recv_script_    ; }
||||||| 5d07ad0a
    bool               exit()    const { return exit_   ; }
=======
>>>>>>> release_26.4.27

private:

    bool        daemon_;
    std::string name_;
    std::string address_;
    std::string group_;
    std::string sst_;
    std::string donor_;
    std::string options_;
    std::string log_;
<<<<<<< HEAD
    std::string cfg_;
    std::string recv_script_;
    bool        wait_for_recv_script_exit_;
    std::string post_recv_script_;
||||||| 5d07ad0a
    std::string cfg_;
=======
>>>>>>> release_26.4.27
    std::string workdir_;
<<<<<<< HEAD
    bool        extended_exit_codes_;
#if defined(WITH_COREDUMPER) && WITH_COREDUMPER
    std::string coredumper_;
#endif
    bool exit_; /* Exit on --help or --version */
||||||| 5d07ad0a
    bool exit_; /* Exit on --help or --version */
=======
    std::string cfg_;
>>>>>>> release_26.4.27

    bool isValidStringRegex(const std::string& str);
    bool validateSingleOption(const std::string& option,
                              const std::string& optionName);
    bool validate();

}; /* class Config */

std::ostream& operator << (std::ostream&, const Config&);

} /* namespace garb */

#endif /* _GARB_CONFIG_HPP_ */
