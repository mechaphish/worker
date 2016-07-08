#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

from datetime import datetime

import fuzzer
import time

from .afl import AFLWorker
import worker.workers
LOG = worker.workers.LOG.getChild('were_rabbit_worker')
LOG.setLevel('DEBUG')

class WereRabbitWorker(AFLWorker):
    """ AFL's crash exploration mode.
    Affectionately named the 'Peruvian Were Rabbit' by lcamtuf.
    """
    def __init__(self):
        super(WereRabbitWorker, self).__init__()
        self._workername = 'were_rabbit'
        self._workdir = "/dev/shm/crash_work"

    def _start(self, job):
        """Run Were Rabbit crash explorer."""
        self._timeout = job.limit_time

        # first, get the crahes we have currently discovered, these will be used
        # to seed the crash explorer
        LOG.info("Gathering all found crashes")
        all_crashes = list(self._cbn.crashes)
        if len(all_crashes) > 0:
            self._seen.update(str(c.blob) for c in all_crashes)
        else:
            raise Exception("No crashes found to explore (why was I scheduled?)")

        self._last_sync_time = datetime.min

        LOG.info("Starting up crash fuzzer")
        self._fuzzer = fuzzer.Fuzzer(self._cbn.path, self._workdir,
                                     self._job.limit_cpu, seeds=self._seen,
                                     create_dictionary=True, crash_mode=True)

        LOG.info("Created crash fuzzer")
        self._fuzzer.start()
        for _ in range(15):
            if self._fuzzer.alive:
                break
            time.sleep(1)
        else:
            raise Exception("Crash fuzzer failed to start")

        LOG.info("Started crash fuzzer")

        while self._timeout is None or self._runtime < self._timeout:
            time.sleep(5)
            self._runtime += 5

            LOG.debug("Checking results...")

            for c in self._fuzzer.crashes():
                self._check_crash(c)
            for c in self._fuzzer.queue():
                self._check_test(c)

            LOG.debug("Syncing new testcases...")
            n = self._sync_new_tests()
            LOG.debug("... synced %d new testcases!", n)

    def _run(self, job):
        try:
            self._start(job)
        finally:
            if self._fuzzer is not None:
                self._fuzzer.kill()
