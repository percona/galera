/*
 * Copyright (C) 2009-2025 Codership Oy <info@codership.com>
 *
 */

#ifndef __GU_MUTEX__
#define __GU_MUTEX__

#include "gu_macros.h"
#include "gu_threads.h"
#include "gu_throw.hpp"
#include "gu_logger.hpp"
#include "gu_abort.h"

#include <cerrno>
#include <cstring>
#include <cassert>
#include <cstdlib> // abort()

#if !defined(GU_DEBUG_MUTEX) && !defined(NDEBUG)
#define GU_MUTEX_DEBUG
#endif

/* Say t-1 locks mutex m1 and then enter cond-wait. This wait will inherently
unlock m1 there-by allowing other thread to take over m1. This action will
cause owned_ to get reset to new thread (say t2).
When t-1 try to unlock it the check for owned will fail.*/

namespace gu
{
    class Mutex
    {
    public:

        Mutex () : value_()
#ifdef GU_MUTEX_DEBUG
                 , owned_()
                 , locked_()
#endif /* GU_MUTEX_DEBUG */
        {
            gu_mutex_init (&value_, NULL); // always succeeds
        }

        ~Mutex ()
        {
            int const err(gu_mutex_destroy (&value_));
            if (gu_unlikely(err != 0))
            {
                log_fatal << "Mutex destroy failed: " << err << " ("
                          << strerror(err) << "), Aborting.";
                gu_abort();
            }
        }

        void lock() const
        {
            int const err(gu_mutex_lock(&value_));
            if (gu_likely(0 == err))
            {
#ifdef GU_MUTEX_DEBUG
                locked_ = true;
                owned_  = gu_thread_self();
#endif /* GU_MUTEX_DEBUG */
            }
            else
            {
                log_fatal << "Mutex lock failed: " << err << " ("
                          << strerror(err) << "), Aborting.";
                // Do not throw exception here because it will be
                // uncaught in many destructors.
                gu_abort();
            }
        }

        void unlock() const
        {
            // this is not atomic, but the presumption is that unlock()
            // should never be called before preceding lock() completes
#if defined(GU_DEBUG_MUTEX) || defined(GU_MUTEX_DEBUG)
            assert(locked());
            assert(owned());
#if defined(GU_MUTEX_DEBUG)
            locked_ = false;
#endif /* GU_MUTEX_DEBUG */
            disown();
#endif /* GU_DEBUG_MUTEX */
            int const err(gu_mutex_unlock(&value_));
            if (gu_unlikely(0 != err))
            {
                log_fatal << "Mutex unlock failed: " << err << " ("
                          << strerror(err) << "), Aborting.";
                gu_abort();
            }
        }

        gu_mutex_t& impl() const { return value_; }

#if defined(GU_DEBUG_MUTEX)
        bool locked() const { return gu_mutex_locked(&value_); }
        bool owned()  const { return locked() && gu_mutex_owned(&value_);  }
        void disown() const { gu_mutex_disown(&value); }
#elif defined(GU_MUTEX_DEBUG)
        bool locked() const { return locked_; }
        bool owned()  const { return locked() && gu_thread_equal(owned_,gu_thread_self()); }
        void disown() const
        {
            memset(&owned_, 0, sizeof(owned_));
        }
#endif /* GU_DEBUG_MUTEX */
    protected:

        gu_mutex_t  mutable value_;
#ifdef GU_MUTEX_DEBUG
        gu_thread_t mutable owned_;
        bool        mutable locked_;
#endif /* GU_MUTEX_DEBUG */

    private:

        Mutex (const Mutex&);
        Mutex& operator= (const Mutex&);

        friend class Lock;
    };

#ifdef PXC
#ifdef HAVE_PSI_INTERFACE

    /* MutexWithPFS can be instrumented with MySQL performance schema.
    (provided mysql has performance schema enabled).
    In order to faciliate instead of direclty creating instance of
    pthread mutex, mysql mutex instances is created using callback.
    MutexWithPFS just act as wrapper invoking appropriate calls from
    MySQL space. */
    class MutexWithPFS
    {
    public:

        MutexWithPFS (wsrep_pfs_instr_tag_t tag) : value()
#ifdef GU_MUTEX_DEBUG
                 , owned_()
                 , locked_()
#endif /* GU_MUTEX_DEBUG */
                 , m_tag(tag)
        {
            pfs_instr_callback(WSREP_PFS_INSTR_TYPE_MUTEX,
                               WSREP_PFS_INSTR_OPS_INIT,
                               m_tag, reinterpret_cast<void**> (&value),
                               NULL, NULL);
        }

        ~MutexWithPFS ()
        {
            pfs_instr_callback(WSREP_PFS_INSTR_TYPE_MUTEX,
                               WSREP_PFS_INSTR_OPS_DESTROY,
                               m_tag, reinterpret_cast<void**> (&value),
                               NULL, NULL);
        }

        void lock()
        {
            pfs_instr_callback(WSREP_PFS_INSTR_TYPE_MUTEX,
                               WSREP_PFS_INSTR_OPS_LOCK,
                               m_tag, reinterpret_cast<void**> (&value),
                               NULL, NULL);
        }

        void unlock()
        {
            pfs_instr_callback(WSREP_PFS_INSTR_TYPE_MUTEX,
                               WSREP_PFS_INSTR_OPS_UNLOCK,
                               m_tag, reinterpret_cast<void**> (&value),
                               NULL, NULL);
        }

#if defined(GU_DEBUG_MUTEX)
        bool locked() const { return gu_mutex_locked(&value_); }
        bool owned()  const { return locked() && gu_mutex_owned(&value_);  }
#elif defined(GU_MUTEX_DEBUG)
        bool locked() const { return true; }
        bool owned()  const { return true; }
#endif /* GU_DEBUG_MUTEX */

   protected:
        gu_mutex_t* value;
#ifdef GU_MUTEX_DEBUG
        gu_thread_t mutable owned_;
        bool        mutable locked_;
#endif /* GU_MUTEX_DEBUG */

    private:

        wsrep_pfs_instr_tag_t m_tag;

        MutexWithPFS (const MutexWithPFS&);
        MutexWithPFS& operator= (const MutexWithPFS&);

        friend class Lock;
    };
#endif /* HAVE_PSI_INTERFACE */
#endif /* PXC */

    class RecursiveMutex
    {
    public:
        RecursiveMutex() : mutex_()
        {
            pthread_mutexattr_t mattr;
            pthread_mutexattr_init(&mattr);
            pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
            pthread_mutex_init(&mutex_, &mattr);
            pthread_mutexattr_destroy(&mattr);
        }

        ~RecursiveMutex()
        {
            pthread_mutex_destroy(&mutex_);
        }

        void lock()
        {
            if (pthread_mutex_lock(&mutex_)) gu_throw_fatal;
        }

        void unlock()
        {
            if (pthread_mutex_unlock(&mutex_)) gu_throw_fatal;
        }

    private:
        RecursiveMutex(const RecursiveMutex&);
        void operator=(const RecursiveMutex&);

        pthread_mutex_t mutex_;
    };
}

#endif /* __GU_MUTEX__ */
