/* Copyright (C) 2011-2013 Codership Oy <info@codership.com> */

#include "garb_config.hpp"
#include "garb_logger.hpp"
#include <gcs.hpp>

#include <gu_crc32c.h>
#include <gu_logger.hpp>
#include <gu_throw.hpp>
#include <wsrep_api.h>

#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <iostream>
#include <fstream>
#ifdef PXC
#include <errno.h>
#include <regex>
#endif /* PXC */

namespace garb
{

    static void
    strip_quotes(std::string& s)
    {
        /* stripping no more than one pair of quotes */
        if ('"' == *s.begin() && '"' == *s.rbegin())
        {
            std::string stripped(s.substr(1, s.length() - 2));
            s = stripped;
        }
    }

    std::string const Config::DEFAULT_SST(WSREP_STATE_TRANSFER_TRIVIAL);

Config::Config (int argc, char* argv[])
    : daemon_  (false),
      name_    (GCS_ARBITRATOR_NAME),
      address_ (),
      group_   ("my_test_cluster"),
      sst_     (DEFAULT_SST),
      donor_   (),
      options_ (),
      log_     (),
      cfg_     (),
      recv_script_ (),
      wait_for_recv_script_exit_(false),
      post_recv_script_(),
      workdir_ (),
      extended_exit_codes_(false),
#if defined(WITH_COREDUMPER) && WITH_COREDUMPER
      coredumper_ (),
#endif
      exit_    (false)
{
    po::options_description other ("Other options");
    other.add_options()
        ("version,v", "Print version & exit")
        ("help,h",    "Show help message & exit")
        ;

    // only these are read from cfg file
    po::options_description config ("Configuration");
    config.add_options()
        ("daemon,d", "Become daemon")
#if defined(WITH_COREDUMPER) && WITH_COREDUMPER
        ("coredumper", po::value<std::string>(&coredumper_), "Path to dump core file on crash")
#endif
        ("name,n",      po::value<std::string>(&name_),        "Node name")
        ("address,a",   po::value<std::string>(&address_),     "Group address")
        ("group,g",     po::value<std::string>(&group_),       "Group name")
        ("sst",         po::value<std::string>(&sst_),         "SST request string")
        ("donor",       po::value<std::string>(&donor_),       "SST donor name")
        ("options,o",   po::value<std::string>(&options_),     "GCS/GCOMM option list")
        ("log,l",       po::value<std::string>(&log_),         "Log file")
        ("recv-script", po::value<std::string>(&recv_script_), "SST request receive script")
        ("post-recv-script", po::value<std::string>(&post_recv_script_), "Post SST script")
        ("wait-for-recv-script-exit", "Wait for recv-script graceful exit (don't kill it after transfer).")
        ("extended-exit-codes", "Report extended exit codes")
        ("workdir,w",po::value<std::string>(&workdir_),
         "Daemon working directory")
        ;

    po::options_description cfg_opt;
    cfg_opt.add_options()
        ("cfg,c",    po::value<std::string>(&cfg_),     "Configuration file")
        ;

    // these are accepted on the command line
    po::options_description cmdline_opts;
    cmdline_opts.add(config).add(cfg_opt).add(other);

    // we can submit address without option
    po::positional_options_description p;
    p.add("address", -1);

    po::variables_map vm;
    store(po::command_line_parser(argc, argv).
          options(cmdline_opts).positional(p).run(), vm);
    notify(vm);

    if (!validate())
    {
        exit_ = true;
        return;
    }

    if (vm.count("help"))
    {
        std::cerr << "\nUsage: " << argv[0] << " [options] [group address]\n"
                  << cmdline_opts << std::endl;
        exit_= true;
        return;
    }

    if (vm.count("version"))
    {
        log_info << GALERA_VER << "." << GALERA_REV;
        exit_= true;
        return;
    }

    if (vm.count("cfg"))
    {
        std::ifstream ifs(cfg_.c_str());

        if (!ifs.good())
        {
#ifdef PXC
            gu_throw_error(errno)
#else
            gu_throw_error(ENOENT)
#endif /* PXC */
                << "Failed to open configuration file '" << cfg_
                << "' for reading.";
        }

        store(parse_config_file(ifs, config), vm);
        notify(vm);
    }

    if (!vm.count("address"))
    {
        gu_throw_error(EDESTADDRREQ) << "Group address not specified";
    }

    if (!vm.count("group"))
    {
        gu_throw_error(EDESTADDRREQ) << "Group name not specified";
    }

    if (vm.count("daemon"))
    {
        daemon_ = true;
    }

    if (vm.count("wait-for-recv-script-exit")) {
        wait_for_recv_script_exit_ = true;
    }
    if (vm.count("extended-exit-codes")) {
        extended_exit_codes_ = true;
    }

    /* Seeing how https://svn.boost.org/trac/boost/ticket/850 is fixed long and
     * hard, it becomes clear what an undercooked piece of... cake(?) boost is.
     * - need to strip quotes manually if used in config file.
     * (which is done in a very simplistic manner, but should work for most) */
    strip_quotes(name_);
    strip_quotes(address_);
    strip_quotes(group_);
    strip_quotes(sst_);
    strip_quotes(recv_script_);
    strip_quotes(post_recv_script_);
    strip_quotes(donor_);
    strip_quotes(options_);
    strip_quotes(log_);
    strip_quotes(workdir_);
    strip_quotes(cfg_);

    if (options_.length() > 0) options_ += "; ";
    options_ += "gcs.fc_limit=9999999; gcs.fc_factor=1.0; gcs.fc_single_primary=yes";
    if (!workdir_.empty())
    {
        options_ += " base_dir=" + workdir_ + ";";
    }

    // Add implicit socket.ssl=YES if needed.
    // We need to add it if socket.ssl_key or socket.ssl_cert is specified
    // and socket.ssl is not specified.
    // This is the same logic as Galera does in gu_asio.cpp::init_use_ssl()
    if ((options_.find("socket.ssl_key") != std::string::npos ||
         options_.find("socket.ssl_cert") != std::string::npos)
         &&
         // this way we avoid tokenizing and stripping the string
        (options_.find("socket.ssl=") == std::string::npos &&
         options_.find("socket.ssl ") == std::string::npos))
    {
        options_ += "; socket.ssl=YES";
    }

    // this block must be the very last.
    gu_conf_self_tstamp_on();
    if (vm.count("log"))
    {
        set_logfile (log_);
    }
    else if (daemon_) /* if no log file given AND daemon operation requested -
                       * log to syslog */
    {
        gu_conf_self_tstamp_off();
        set_syslog();
    }

    gu_crc32c_configure();
}

bool Config::isValidStringRegex(const std::string& str)
{
    // Only ASCII printable characters (space to ~)
    static const std::regex validPattern("^[ -~]+$");
    return std::regex_match(str, validPattern);
}

bool Config::validateSingleOption(const std::string& option,
                                  const std::string& optionName)
{
    if (option.empty() || isValidStringRegex(option))
    {
        return true;
    }
    std::cerr << "\n'" << optionName
              << "' option contains non-printable ASCII characters\n";
    return false;
}

/* Do a sanity check for all string options, if they contain only valid
characters */
bool Config::validate()
{
    return validateSingleOption(name_, "name")
           && validateSingleOption(address_, "address")
           && validateSingleOption(group_, "group")
           && validateSingleOption(sst_, "sst")
           && validateSingleOption(donor_, "donor")
           && validateSingleOption(options_, "options")
           && validateSingleOption(log_, "log")
           && validateSingleOption(recv_script_, "recv-script")
           && validateSingleOption(post_recv_script_, "post-recv-script")
           && validateSingleOption(workdir_, "workdir")
#if defined(WITH_COREDUMPER) && WITH_COREDUMPER
           && validateSingleOption(coredumper_, "coredumper")
#endif
           && validateSingleOption(cfg_, "cfg");
}

std::ostream& operator << (std::ostream& os, const Config& c)
{
    os << "\n\tdaemon:      " << c.daemon()
       << "\n\tname:        " << c.name()
       << "\n\taddress:     " << c.address()
       << "\n\tgroup:       " << c.group()
       << "\n\tsst:         " << c.sst()
       << "\n\tdonor:       " << c.donor()
       << "\n\toptions:     " << c.options()
       << "\n\tcfg:         " << c.cfg()
       << "\n\tlog:         " << c.log()
       << "\n\trecv_script: " << c.recv_script()
       << "\n\tworkdir: " << c.workdir();
    return os;
}

}
