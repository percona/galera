//
// Copyright (C) 2015 Codership Oy <info@codership.com>
//


#include "galera_view.hpp"

#include <algorithm>

galera::View::View()
    :
    members_()
{ }

galera::View::View(const wsrep_view_info_t& view_info)
    :
    members_()
{
    for (int i(0); i < view_info.memb_num; ++i)
    {
        members_.insert(view_info.members[i].id);
    }
}

#ifdef PXC
/* An arbitrator (garbd) never applies write sets, so it never sends NBO end
   and must not be waited for by the NBO end barrier. garbd always joins as
   stateless (gcs.stateless=yes) and with an empty incoming address, whatever
   its name. A data node can also be stateless (so it is never chosen as
   donor), but it applies write sets and has an incoming address, so it is
   still waited for. */
static bool is_arbitrator(const gcs_act_cchange::member& member)
{
    return (member.stateless_ && member.incoming_.empty());
}

galera::View::View(const gcs_act_cchange& conf)
    :
    members_()
{
    /* Arbitrators are left out only if every other member does the same.
       Otherwise (older nodes in the view, or a CC written by an older node)
       wait for all members as before, so that all nodes end the NBO at the
       same point. */
    bool skip_arbitrators(true);
    for (size_t i(0); i < conf.memb.size(); ++i)
    {
        if (!is_arbitrator(conf.memb[i]) && !conf.memb[i].arb_nbo_)
        {
            skip_arbitrators = false;
            break;
        }
    }

    for (size_t i(0); i < conf.memb.size(); ++i)
    {
        if (skip_arbitrators && is_arbitrator(conf.memb[i])) continue;
        members_.insert(conf.memb[i].uuid_);
    }

    /* If every member looks like an arbitrator, subset_of() would be
       trivially true and NBO would end on the first NBO end message, so wait
       for all members instead. */
    if (members_.empty())
    {
        for (size_t i(0); i < conf.memb.size(); ++i)
        {
            members_.insert(conf.memb[i].uuid_);
        }
    }
}
#endif /* PXC */

galera::View::~View()
{ }


bool galera::View::subset_of(const MembSet& mset) const
{
    return std::includes(mset.begin(), mset.end(),
                         members_.begin(), members_.end(), UUIDCmp());
}
