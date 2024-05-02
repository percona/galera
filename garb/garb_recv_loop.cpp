/* Copyright (C) 2011-2023 Codership Oy <info@codership.com> */

#include "garb_recv_loop.hpp"

#include <signal.h>
#include "process.h"
#include "garb_raii.h" // Garb_gcs_action_buffer_guard

namespace garb
{

static Gcs*
global_gcs(0);

void
signal_handler (int signum)
{
    log_info << "Received signal " << signum;
    global_gcs->close();
}

void
RecvLoop::close_connection()
{
    if (!closed_)
    {
        gcs_.close();
        closed_ = true;
    }
}

RecvLoop::RecvLoop (const Config& config)
    :
    config_(config),
    gconf_ (),
    params_(gconf_),
    parse_ (gconf_, config_.options()),
    gcs_   (gconf_, config_.name(), config_.address(), config_.group()),
    uuid_  (GU_UUID_NIL),
    seqno_ (GCS_SEQNO_ILL),
    proto_ (0),
    rcode_ (0),
    closed_(false),
    sst_source_uuid_(),
    sst_requested_(false),
    sst_status_keep_running_(true),
    sst_ended_(false),
    sst_terminated_(false)
{
    /* set up signal handlers */
    global_gcs = &gcs_;

    struct sigaction sa;

    memset (&sa, 0, sizeof(sa));
#ifdef PXC
    sigemptyset(&sa.sa_mask);
#endif /* PXC */
    sa.sa_handler = signal_handler;

    if (sigaction (SIGTERM, &sa, NULL))
    {
        gu_throw_error(errno) << "Falied to install signal handler for signal "
                              << "SIGTERM";
    }

    if (sigaction (SIGINT, &sa, NULL))
    {
        gu_throw_error(errno) << "Falied to install signal handler for signal "
                              << "SIGINT";
    }

    process_ = std::make_shared<process>(config_.recv_script().c_str(), "rw", nullptr, false);
    loop();
}

void pipe_to_log(FILE* pipe) {
    const int out_len = 1024;
    char out_buf[out_len];
    char* p;
    while ((p = fgets(out_buf, out_len, pipe)) != NULL) {
        log_info << "[SST script] " << out_buf;
    }
}

/* return true to exit loop */
bool
RecvLoop::one_loop()
{
    gcs_action act;

    gcs_.recv (act);

    Garb_gcs_action_buffer_guard ag{&act};

    switch (act.type)
    {
    case GCS_ACT_WRITESET:
        seqno_ = act.seqno_g;
        if (gu_unlikely(proto_ == 0 && !(seqno_ & 127)))
            /* report_interval_ of 128 in old protocol */
        {
            gcs_.set_last_applied (gu::GTID(uuid_, seqno_));
        }
        break;
    case GCS_ACT_COMMIT_CUT:
        break;
    case GCS_ACT_STATE_REQ:
        /* we can't donate state */
        gcs_.join (gu::GTID(uuid_, seqno_),-ENOSYS);
        break;
    case GCS_ACT_CCHANGE:
    {
        gcs_act_cchange const cc(act.buf, act.size);

        if (cc.conf_id > 0) /* PC */
        {
            int const my_idx(act.seqno_g);
            assert(my_idx >= 0);

            gcs_node_state const my_state(cc.memb[my_idx].state_);

            if (GCS_NODE_STATE_PRIM == my_state && !sst_requested_)
            {
                uuid_  = cc.uuid;
                seqno_ = cc.seqno;
                sst_requested_ = true;
                auto sst_source_idx =  gcs_.request_state_transfer (config_.sst(),config_.donor());
                sst_source_uuid_ = cc.memb[sst_source_idx].uuid_;
                if(config_.recv_script().empty()) {
                    gcs_.join(gu::GTID(cc.uuid, cc.seqno), 0);
                } else {
                    log_info << "Starting SST script";
                    process_->execute("rw", NULL);

                     std::thread err_log_thd([&](){
                        pipe_to_log(process_->err_pipe());
                        log_info << "SST script ended";
                        sst_ended_ = true;
                        gcs_.close(true);
                    });
                    sst_err_log_.swap(err_log_thd);

                    std::thread out_log_thd([&](){
                        pipe_to_log(process_->pipe());
                    });
                    sst_out_log_.swap(out_log_thd);

                    std::thread sst_status_thd([&](){
                        while(sst_status_keep_running_) {

                            auto st = gcs_.state_for(sst_source_uuid_);
                            if(st == GCS_NODE_STATE_MAX) {
                                log_info << "Donor is no longer in the cluster, interrupting script";
                                sst_terminated_ = true;
                                process_->terminate();
                                break;
                            } else if(st != GCS_NODE_STATE_DONOR) {
                                // The donor is going back to SYNCED. If SST streaming didn't start yet,
                                // it won't.
                                // Send SIGTERM to the script and let it handle this situation.
                                log_info << "Donor no longer in donor state, interrupting script";
                                sst_terminated_ = true;
                                process_->terminate();
                                break;
                            }
                            std::this_thread::sleep_for(std::chrono::seconds(1));
                        }
                    });
                    sst_status_thread_.swap(sst_status_thd);
                }
            }

            proto_ = gcs_.proto_ver();
        }
        else
        {
            if (cc.memb.size() == 0) // SELF-LEAVE after closing connection
            {
                if(!config_.recv_script().empty()) {
                    if (sst_terminated_) {
                        log_info << "SST script already terminated";
                        rcode_ = process_->wait();
                        sst_err_log_.join();
                        sst_out_log_.join();
                        sst_status_keep_running_ = false;
                        sst_status_thread_.join();
                        log_info << "Exiting main loop";
                        return true;
                    } else if(sst_ended_) {
                        // Good path: we decided to close the connection after the receiver script closed its
                        // standard output. We wait for it to exit and return its error code.
                        log_info << "Waiting for SST script to stop";
                        rcode_ = process_->wait();
                        log_info << "SST script stopped";
                        sst_err_log_.join();
                        sst_out_log_.join();
                        sst_status_keep_running_ = false;
                        sst_status_thread_.join();
                        log_info << "Exiting main loop";
                        return true;
                    } else {
                        // Error path: we are closing the connection because there is an SST error,
                        // such as a non existent donor side SST script was specified
                        // As the receiver side script is already running, and is most likely waiting for a TCP
                        // connection, we terminate it and report an error.
                        log_info << "Terminating SST script";
                        process_->terminate();
                        sst_err_log_.join();
                        sst_out_log_.join();
                        sst_status_keep_running_ = false;
                        sst_status_thread_.join();
                        log_info << "Exiting main loop";
                        rcode_ = 1;
                        return true;
                    }
                } else {
                        log_info << "Exiting main loop";
                        rcode_ = 0;
                        return true;
                }
            }
            uuid_  = GU_UUID_NIL;
            seqno_ = GCS_SEQNO_ILL;
        }

        if (config_.sst() != Config::DEFAULT_SST)
        {
            // we requested custom SST, so we're done here
            if(config_.recv_script().empty() && !closed_) {
                gcs_.close(true);
                closed_ = true;
            }
        }

        break;
    }
    case GCS_ACT_INCONSISTENCY:
        // something went terribly wrong, restart needed
        close_connection();
        break;
    case GCS_ACT_JOIN:
    case GCS_ACT_SYNC:
    case GCS_ACT_FLOW:
    case GCS_ACT_VOTE:
    case GCS_ACT_SERVICE:
    case GCS_ACT_ERROR:
    case GCS_ACT_UNKNOWN:
        break;
    }

    if (act.buf)
    {
        ::free(const_cast<void*>(act.buf));
        act.buf = nullptr;
    }

    return false;
}

void
RecvLoop::loop()
{
    while (true)
    {
        try
        {
            if (one_loop()) return;
        }
        catch(gu::Exception& e)
        {
            log_error << e.what();
            close_connection();
            rcode_ = 1;
            switch (e.get_errno())
            {
                case -GCS_CLOSED_ERROR:
                case EHOSTUNREACH: /* no route to host */
                    throw;
            }
            /* continue looping to clear recv queue */
        }
    }
}

} /* namespace garb */
