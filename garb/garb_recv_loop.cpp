/* Copyright (C) 2011-2020 Codership Oy <info@codership.com> */

#include "garb_recv_loop.hpp"

#include <signal.h>
#include <thread> 
#include <atomic> 
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
    rcode_ (0)
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

    rcode_ = loop();
}

void pipe_to_log(FILE* pipe) {
    const int out_len = 1024;
    char out_buf[out_len];
    char* p;
    while ((p = fgets(out_buf, out_len, pipe)) != NULL) {
        log_info << "[SST script] " << out_buf;
    }
}

int
RecvLoop::loop()
{
    process p(config_.recv_script().c_str(), "rw", NULL, false);
    std::thread sst_out_log;
    std::thread sst_err_log;

    gu_uuid_t sst_source_uuid;
    bool sst_requested = false;
    std::atomic_bool sst_status_keep_running{true};
    std::thread sst_status_thread;

    bool sst_ended = false;
    bool sst_terminated = false;
    while (1)
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

                if (GCS_NODE_STATE_PRIM == my_state && !sst_requested)
                {
                    uuid_  = cc.uuid;
                    seqno_ = cc.seqno;
                    sst_requested = true;
                    auto sst_source_idx =  gcs_.request_state_transfer (config_.sst(),config_.donor());
                    sst_source_uuid = cc.memb[sst_source_idx].uuid_;
                    if(config_.recv_script().empty()) {
                        gcs_.join(gu::GTID(cc.uuid, cc.seqno), 0);
                    } else {
                        log_info << "Starting SST script";
                        p.execute("rw", NULL);

                        sst_err_log = std::thread([&](){
                            pipe_to_log(p.err_pipe());
                            log_info << "SST script ended";
                            sst_ended = true;
                            gcs_.close(true);
                        });

                        sst_out_log = std::thread([&](){
                            pipe_to_log(p.pipe());
                        });

                        sst_status_thread = std::thread([&](){
                            while(sst_status_keep_running) {

                              auto st = gcs_.state_for(sst_source_uuid);
                              if(st == GCS_NODE_STATE_MAX) {
                                  log_info << "Donor is no longer in the cluster, interrupting script";
                                  sst_terminated = true;
                                  p.terminate();
                                  break;
                              } else if(st != GCS_NODE_STATE_DONOR) {
                                  // The donor is going back to SYNCED. If SST streaming didn't start yet,
                                  // it won't.
                                  // Send SIGTERM to the script and let it handle this situation.
                                  log_info << "Donor no longer in donor state, interrupting script";
                                  sst_terminated = true;
                                  p.terminate();
                                  break;
                              }
                              std::this_thread::sleep_for(std::chrono::seconds(1));
                            }
                        });
                    }
                }

                proto_ = gcs_.proto_ver();
            }
            else
            {
                if (cc.memb.size() == 0) // SELF-LEAVE after closing connection
                {
                    if(!config_.recv_script().empty()) {
                      if (sst_terminated) {
                            log_info << "SST script already terminated";
                            const auto ret = p.wait();
                            sst_err_log.join();
                            sst_out_log.join();
                            sst_status_keep_running = false;
                            sst_status_thread.join();
                            log_info << "Exiting main loop";
                            return ret;
                        } else if(sst_ended) {
                            // Good path: we decided to close the connection after the receiver script closed its
                            // standard output. We wait for it to exit and return its error code.
                            log_info << "Waiting for SST script to stop";
                            const auto ret = p.wait();
                            log_info << "SST script stopped";
                            sst_err_log.join();
                            sst_out_log.join();
                            sst_status_keep_running = false;
                            sst_status_thread.join();
                            log_info << "Exiting main loop";
                            return ret;
                        } else {
                            // Error path: we are closing the connection because there is an SST error,
                            // such as a non existent donor side SST script was specified
                            // As the receiver side script is already running, and is most likely waiting for a TCP
                            // connection, we terminate it and report an error.
                            log_info << "Terminating SST script";
                            p.terminate();
                            sst_err_log.join();
                            sst_out_log.join();
                            sst_status_keep_running = false;
                            sst_status_thread.join();
                            log_info << "Exiting main loop";
                            return 1;
                        }
                    } else {
                            log_info << "Exiting main loop";
                            return 0;
                    }
                }
                uuid_  = GU_UUID_NIL;
                seqno_ = GCS_SEQNO_ILL;
            }

            if (config_.sst() != Config::DEFAULT_SST)
            {
                // we requested custom SST, so we're done here
                if(config_.recv_script().empty()) {
                    gcs_.close(true);
                }
            }

            break;
        }
        case GCS_ACT_INCONSISTENCY:
            // something went terribly wrong, restart needed
            gcs_.close(true);
            return 2;
        case GCS_ACT_JOIN:
        case GCS_ACT_SYNC:
        case GCS_ACT_FLOW:
        case GCS_ACT_VOTE:
        case GCS_ACT_SERVICE:
        case GCS_ACT_ERROR:
        case GCS_ACT_UNKNOWN:
            break;
        }
    }
    return 0;
}

} /* namespace garb */
