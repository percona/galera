/* Copyright (C) 2011-2016 Codership Oy <info@codership.com> */

#ifndef _GARB_GCS_HPP_
#define _GARB_GCS_HPP_

#include <gcs.hpp>
#include <gu_config.hpp>

#define GCS_CLOSED_ERROR -EBADFD

namespace garb
{

class Gcs
{
public:

    Gcs (gu::Config&        conf,
         const std::string& name,
         const std::string& address,
         const std::string& group);

    ~Gcs ();

    long recv (gcs_action& act);

    ssize_t request_state_transfer (const std::string& request,
                                 const std::string& donor);

    void join (const gu::GTID&, int code);

    void set_last_applied(const gu::GTID&);

    int  proto_ver() const { return gcs_proto_ver(gcs_); }

    gcs_node_state_t state_for(gu_uuid_t uuid);

    void close (bool explicit_close = false);

private:

    bool        closed_;
    gcs_conn_t* gcs_;

    Gcs (const Gcs&);
    Gcs& operator= (const Gcs&);

}; /* class Gcs */

} /* namespace garb */

#endif /* _GARB_GCS_HPP_ */
