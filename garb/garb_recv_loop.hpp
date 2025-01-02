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
