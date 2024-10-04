#include <assert.h>
#include "gu_conf.h"

#ifdef PXC
/* If the code around is compiled with HAVE_PSI_INTERFACE defined,
   it uses pfs_instr_callback for mutexes and conditions creation.
   If HAVE_PSI_INTERFACE is not defined, the code around uses Galera
   objects directly.
   Because of CMake scripts structure, it is not possible to compile
   Galera lib with HAVE_PSI_INTERFACE defined and garbd with HAVE_PSI_INTERFACE
   not defined. However, for garbd there is no "server side" which is PSI interface
   provider (like for Galera lib).
   The below function mocks PSI interface allowing garbd to work when compiled
   with HAVE_PSI_INTERFACE defined. */
static void dummy_pfs_cb(wsrep_pfs_instr_type_t type, wsrep_pfs_instr_ops_t ops,
                         wsrep_pfs_instr_tag_t tag,
                         void **value __attribute__((unused)),
                         void **alliedvalue __attribute__((unused)),
                         const void *ts __attribute__((unused))) {

  if (type == WSREP_PFS_INSTR_TYPE_MUTEX) {
    assert (value != nullptr);
    switch (ops) {
      case WSREP_PFS_INSTR_OPS_INIT: {
        gu_mutex_t *mutex = new gu_mutex_t();
       //  fprintf(stderr, "KH: WSREP_PFS_INSTR_OPS_INIT x%llX\n", (unsigned long long)mutex);
        gu_mutex_init (mutex, nullptr);
        *value = mutex;

        break;
      }

      case WSREP_PFS_INSTR_OPS_DESTROY: {
        gu_mutex_t *mutex = reinterpret_cast<gu_mutex_t *>(*value);
        assert(mutex != nullptr);

        // fprintf(stderr, "KH: WSREP_PFS_INSTR_OPS_DESTROY x%llX\n", (unsigned long long)mutex);
        gu_mutex_destroy (mutex);
        delete mutex;
        *value = nullptr;

        break;
      }

      case WSREP_PFS_INSTR_OPS_LOCK: {
        gu_mutex_t *mutex = reinterpret_cast<gu_mutex_t *>(*value);
        assert(mutex != nullptr);

        gu_mutex_lock(mutex);

        break;
      }

      case WSREP_PFS_INSTR_OPS_UNLOCK: {
        gu_mutex_t *mutex = reinterpret_cast<gu_mutex_t *>(*value);
        assert(mutex != nullptr);

        gu_mutex_unlock(mutex);

        break;
      }

      default:
        assert(0);
        break;
    }
  } else if (type == WSREP_PFS_INSTR_TYPE_CONDVAR) {
    assert (value != nullptr);
    switch (ops) {
      case WSREP_PFS_INSTR_OPS_INIT: {
        gu_cond_t *cond = new gu_cond_t();

        gu_cond_init(cond, nullptr);
        *value = cond;

        break;
      }

      case WSREP_PFS_INSTR_OPS_DESTROY: {
        gu_cond_t *cond = reinterpret_cast<gu_cond_t *>(*value);
        assert(cond != nullptr);

        gu_cond_destroy(cond);
        delete cond;
        *value = nullptr;

        break;
      }

      case WSREP_PFS_INSTR_OPS_WAIT: {
        gu_cond_t *cond = reinterpret_cast<gu_cond_t *>(*value);
        gu_mutex_t *mutex = reinterpret_cast<gu_mutex_t *>(*alliedvalue);
        assert(cond != nullptr && mutex != nullptr);

        gu_cond_wait (cond, mutex);

        break;
      }

      case WSREP_PFS_INSTR_OPS_TIMEDWAIT: {
        gu_cond_t *cond = reinterpret_cast<gu_cond_t *>(*value);
        gu_mutex_t *mutex = reinterpret_cast<gu_mutex_t *>(*alliedvalue);
        const timespec *wtime = reinterpret_cast<const timespec *>(ts);
        assert(cond != nullptr && mutex != nullptr);

        gu_cond_timedwait(cond, mutex, wtime);

        break;
      }

      case WSREP_PFS_INSTR_OPS_SIGNAL: {
        gu_cond_t *cond = reinterpret_cast<gu_cond_t *>(*value);
        assert(cond != nullptr);

        gu_cond_signal(cond);

        break;
      }

      case WSREP_PFS_INSTR_OPS_BROADCAST: {
        gu_cond_t *cond = reinterpret_cast<gu_cond_t *>(*value);
        assert(cond != nullptr);

        gu_cond_broadcast(cond);

        break;
      }

      default:
        assert(0);
        break;
    }
  } else if (type == WSREP_PFS_INSTR_TYPE_THREAD) {
    switch (ops) {
      case WSREP_PFS_INSTR_OPS_INIT:
      case WSREP_PFS_INSTR_OPS_DESTROY:
        break;

      default:
        assert(0);
        break;
    }
  } else if (type == WSREP_PFS_INSTR_TYPE_FILE) {
    switch (ops) {
      case WSREP_PFS_INSTR_OPS_CREATE:
      case WSREP_PFS_INSTR_OPS_OPEN:
      case WSREP_PFS_INSTR_OPS_CLOSE:
      case WSREP_PFS_INSTR_OPS_DELETE:
        break;

      default:
        assert(0);
        break;
    }
  }
}

/* register callback for PFS instrumentation */
gu_pfs_instr_cb_t pfs_instr_callback = dummy_pfs_cb;
int gu_conf_set_pfs_instr_callback (gu_pfs_instr_cb_t callback)
{
  // fprintf(stderr, "KH: setting callback to: x%llX\n", (unsigned long long)callback);
  if (callback != nullptr) {
    pfs_instr_callback = callback;
  } else {
    pfs_instr_callback = dummy_pfs_cb;
  }
  return 0;
}
#endif /* PXC */
