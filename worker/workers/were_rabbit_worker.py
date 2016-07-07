from .afl_worker import AFLWorker
import datetime
import fuzzer
import time

import logging
l = logging.getLogger('crs.worker.workers.were_rabbit_worker')
l.setLevel('DEBUG')

class WereRabbitWorker(AFLWorker):
    """
    AFL's crash exploration mode. Affectionately named the 'Peruvian Were Rabbit' by lcamtuf.
    """
    def __init__(self):
        super(WereRabbitWorker, self).__init__()
        self._workername = 'were_rabbit'
        self._workdir = '/dev/shm/crash_work'

    def _run(self, job):
        '''
        Runs Were Rabbit crash explorer with the specified number of cores.
        '''

        self._job = job
        self._cbn = job.cbn
        self._timeout = job.limit_time

        # first, get the crahes we have currently discovered, these will be used to seed the crash explorer
        l.info("Gathering all found crashes")
        all_crashes = list(self._cbn.crashes)
        if len(all_crashes) > 0:
            self._seen.update(str(c.blob) for c in all_crashes)
        else:
            raise Exception("No crashes found to explore (why was I scheduled?)")

        self._last_sync_time = datetime.datetime.min

        l.info("Starting up crash fuzzer")
        self._fuzzer = fuzzer.Fuzzer(
            self._cbn.path, self._workdir, self._job.limit_cpu, seeds=self._seen, create_dictionary=True, crash_mode=True
        )

        l.info("Created crash fuzzer")
        self._fuzzer.start()
        for _ in range(15):
            if self._fuzzer.alive:
                break
            time.sleep(1)
        else:
            raise Exception("Crash fuzzer failed to start")

        l.info("Started crash fuzzer")

        while self._timeout is None or self._runtime < self._timeout:
            time.sleep(5)
            self._runtime += 5

            l.debug("Checking results...")

            for c in self._fuzzer.crashes():
                self._check_crash(c)
            for c in self._fuzzer.queue():
                self._check_test(c)

            l.debug("Syncing new testcases...")
            n = self._sync_new_tests()
            l.debug("... synced %d new testcases!", n)

    def run(self, job):
        try:
            self._run(job)
        finally:
            if self._fuzzer is not None:
                self._fuzzer.kill()
