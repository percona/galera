/* Copyright (C) 2011-2023 Codership Oy <info@codership.com> */

#ifndef _GARB_RECV_LOOP_HPP_
#define _GARB_RECV_LOOP_HPP_

#include "garb_gcs.hpp"
#include "garb_config.hpp"

#include <gu_throw.hpp>
#include <gu_asio.hpp>
#include <common.h> // COMMON_BASE_DIR_KEY

#include <memory>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

#include <pthread.h>

class process;

namespace garb
{

// Do not change exit codes as they are visible to garbd's outside world.
namespace return_code {
    /* Generic */
    const int OK = 0;

    /* codes 1 - 34 can be returned by OS if there is a problem with recv-script
       or post-recv-script (permissions, non-existing file, etc).
       Let's allocate codes 100 - 199 for garbd */
    const int GARBD_EXIT_CODE_BASE = 100;

    const int GENERIC_FAILURE = GARBD_EXIT_CODE_BASE;

    /* The following codes are returned only if 'recv-script' is specified.
       If the recv-script finishes without being terminated by garbd
       its exit code is returned.
       It is up to the script to use exit codes that are not in collision
       with garbd exit codes. */

    /* Donor was accessible, but it disappeared in the middle of SST transfer */
    const int DONOR_DISAPPEARED = GARBD_EXIT_CODE_BASE + 1;
    /* Wrong request, eg. nonexisting donor SST script specified. */
    const int SST_REQUEST_FAILURE = GARBD_EXIT_CODE_BASE + 2;
    /* recv-script didn't finish in 5 seconds after the donor transitioned from
       DONOR state back to SYNC state. Garbd killed the script.
       (possible only if garbd started without --wait-for-recv-script-exit) */
    const int SST_SCRIPT_TERMINATED = GARBD_EXIT_CODE_BASE + 3;

    /* Reserved 99 exit codes. recv-script should use exit codes 0 or > GARBD_EXIT_CODE_LAST*/
    const int GARBD_EXIT_CODE_LAST = GARBD_EXIT_CODE_BASE + 99;
}

class RecvLoop
{
public:

    RecvLoop (const Config&);

    ~RecvLoop () {}

    int returnCode() const { return rcode_; }

private:

    bool one_loop();
    void loop();
    void close_connection(bool explicit_close = false);
    std::string rc_to_string(int rc);
    int return_code(int basic, int extended);

    const Config& config_;
    gu::Config    gconf_;

    struct RegisterParams
    {
        RegisterParams(gu::Config& cnf)
        {
            gu::ssl_register_params(cnf);
            gcs_register_params(cnf);
            cnf.add(COMMON_BASE_DIR_KEY);
        }
    }
        params_;

    struct ParseOptions
    {
        ParseOptions(gu::Config& cnf, const std::string& opt)
        {
            cnf.parse(opt);
            gu::ssl_init_options(cnf);
        }
    }
        parse_;

    Gcs gcs_;

    gu::UUID    uuid_;
    gu::seqno_t seqno_;
    int         proto_;
    int         rcode_;
    bool        closed_;

    gu_uuid_t sst_source_uuid_;
    bool sst_requested_;
    std::atomic_bool sst_status_keep_running_;
    std::atomic_bool sst_ended_;
    std::atomic_bool sst_terminated_;

    std::shared_ptr<process> process_;
    std::thread sst_out_log_;
    std::thread sst_err_log_;
    std::thread sst_status_thread_;
    std::mutex script_end_mtx_;
    std:: condition_variable script_end_cv_;
}; /* RecvLoop */

} /* namespace garb */

#endif /* _GARB_RECV_LOOP_HPP_ */
