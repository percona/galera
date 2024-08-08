/*
 * Copyright (C) 2009-2017 Codership Oy <info@codership.com>
 *
 */

#ifndef __GU_LOCK__
#define __GU_LOCK__

#include "gu_exception.hpp"
#include "gu_logger.hpp"
#include "gu_mutex.hpp"
#include "gu_cond.hpp"
#include "gu_datetime.hpp"

#include <cerrno>
#include <cassert>

namespace gu
{
    class Lock
    {
        const Mutex* mtx_;

#ifdef PXC
#ifdef HAVE_PSI_INTERFACE
        MutexWithPFS* pfs_mtx_;
#endif /* HAVE_PSI_INTERFACE */
#endif /* PXC */

        Lock (const Lock&);
        Lock& operator=(const Lock&);

    public:

        Lock (const Mutex& mtx) : mtx_(&mtx)
#ifdef PXC
#ifdef HAVE_PSI_INTERFACE
            , pfs_mtx_()
#endif
#endif /* PXC */
        {
            mtx_->lock();
        }

        virtual ~Lock ()
        {
#ifdef PXC
#ifdef HAVE_PSI_INTERFACE
            if (pfs_mtx_ != NULL)
            {
                pfs_mtx_->unlock();
                return;
            }
#endif /* HAVE_PSI_INTERFACE */
#endif /* PXC */

            mtx_->unlock();
        }

        inline void wait (const Cond& cond)
        {
#ifdef PXC
#ifdef HAVE_PSI_INTERFACE
            if (pfs_mtx_)
            {
                cond.ref_count++;
                gu_cond_wait (&(cond.cond), pfs_mtx_->value);
                cond.ref_count--;
                return;
            }
#endif /* HAVE_PSI_INTERFACE */
#endif /* PXC */

#ifdef GU_MUTEX_DEBUG
            mtx_->locked_ = false;
            mtx_->disown();
#endif /* GU_MUTEX_DEBUG */
            cond.ref_count++;
            gu_cond_wait (&(cond.cond), &mtx_->impl()); // never returns error
            cond.ref_count--;
#ifdef GU_MUTEX_DEBUG
            mtx_->locked_ = true;
            mtx_->owned_  = gu_thread_self();
#endif /* GU_MUTEX_DEBUG */
        }

        inline void wait (const Cond& cond, const datetime::Date& date)
        {
#ifdef PXC
#ifdef HAVE_PSI_INTERFACE
            if (pfs_mtx_)
            {
                timespec ts;
                date._timespec(ts);
                cond.ref_count++;
                int ret = gu_cond_timedwait (&(cond.cond), pfs_mtx_->value, &ts);
                cond.ref_count--;
                if (gu_unlikely(ret)) gu_throw_error(ret);
                return;
            }
#endif /* HAVE_PSI_INTERFACE */
#endif /* PXC */

            timespec ts;

            date._timespec(ts);
#ifdef GU_MUTEX_DEBUG
            mtx_->locked_ = false;
            mtx_->disown();
#endif /* GU_MUTEX_DEBUG */
            cond.ref_count++;
            int const ret(gu_cond_timedwait (&(cond.cond), &mtx_->impl(), &ts));
            cond.ref_count--;
#ifdef GU_MUTEX_DEBUG
            mtx_->locked_ = true;
            mtx_->owned_  = gu_thread_self();
#endif /* GU_MUTEX_DEBUG */

            if (gu_unlikely(ret)) gu_throw_system_error(ret);
        }


#ifdef PXC
#ifdef HAVE_PSI_INTERFACE
        Lock (const MutexWithPFS& pfs_mtx)
            :
            mtx_(),
            pfs_mtx_(const_cast<gu::MutexWithPFS*>(&pfs_mtx))
        {
            pfs_mtx_->lock();
        }

        inline void wait (const CondWithPFS& cond)
        {
            cond.ref_count++;
            pfs_instr_callback(
                WSREP_PFS_INSTR_TYPE_CONDVAR,
                WSREP_PFS_INSTR_OPS_WAIT,
                cond.m_tag,
                reinterpret_cast<void**>(const_cast<gu_cond_t**>(&(cond.cond))),
                reinterpret_cast<void**>(const_cast<pthread_mutex_t**>(
                                         &(pfs_mtx_->value))),
                NULL);
            cond.ref_count--;
        }

        inline void wait (const CondWithPFS& cond, const datetime::Date& date)
        {
            timespec ts;

            date._timespec(ts);
            cond.ref_count++;
            pfs_instr_callback(
                WSREP_PFS_INSTR_TYPE_CONDVAR,
                WSREP_PFS_INSTR_OPS_WAIT,
                cond.m_tag,
                reinterpret_cast<void**>(const_cast<gu_cond_t**>(&(cond.cond))),
                reinterpret_cast<void**>(const_cast<pthread_mutex_t**>(
                                         &(pfs_mtx_->value))),
                &ts);
            cond.ref_count--;
        }
#endif /* HAVE_PSI_INTERFACE */
#endif /* PXC */
    };
}

#endif /* __GU_LOCK__ */
