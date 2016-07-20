#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

from datetime import datetime
import logging
import time

from farnsworth.models import (Bitmap, Crash, FuzzerStat, Job, Test)
import fuzzer
import rex

import worker.workers
LOG = worker.workers.LOG.getChild('afl')
LOG.setLevel('DEBUG')

logging.getLogger("fuzzer").setLevel("DEBUG")


class AFLWorker(worker.workers.Worker):
    def __init__(self):
        super(AFLWorker, self).__init__()
        self._cbn_paths = None
        self._workername = 'afl'
        self._seen = set()
        self._workdir = '/dev/shm/work'
        self._fuzzer = None
        self._runtime = 0
        self._timeout = None
        self._last_bm = None
        self._last_sync_time = datetime.min

    def _update_bitmap(self):
        bm = self._fuzzer.bitmap()

        if bm is None:
            LOG.critical("unable to retrieve bitmap from fuzzer")
            return
        elif self._last_bm == bm:
            return
        else:
            self._last_bm = bm

        dbm = self._cs.bitmap.first()
        if dbm is not None:
            dbm.blob = bm
        else:   # except Bitmap.DoesNotExist: #pylint:disable=no-member
            dbm = Bitmap(blob=bm, cs=self._cs)
        dbm.save()

    def _check_test(self, t):
        if t in self._seen:
            return
        self._seen.add(t)

        LOG.info("Got test of length %s", len(t))
        self._job.produced_output = True
        self._update_bitmap()
        t = Test.create(cs=self._cs, job=self._job, blob=t, drilled=False)

    def _check_crash(self, t):
        if t in self._seen:
            return
        self._seen.add(t)

        LOG.info("Got crash of length %s", len(t))
        self._job.produced_output = True
        self._update_bitmap()

        # FIXME need good default values for multicbs
        if not self._cs.is_multi_cbn:
            # quick triaging can only be done on single CBs for now
            cbn = self._cbn_paths[0]

            crash_kind = None
            try:
                qc = rex.QuickCrash(cbn, t)
                crash_kind = qc.kind
            except Exception as e:  # pylint: disable=broad-except
                LOG.error("Received a %s exception, shouldn't happen", str(e))

            if crash_kind is None:
                LOG.error("Encountered crash_kind of None, this shouldn't happen")
                LOG.error("Challenge: %s", cbn)
                LOG.error("Crash: %s", t.encode('hex'))
                return

            Crash.create(cs=self._cs, job=self._job, blob=t, drilled=False,
                         kind=qc.kind, crash_pc=qc.crash_pc, bb_count=qc.bb_count)
        else:
            Crash.create(cs=self._cs, job=self._job, blob=t, drilled=False)

    def _sync_new_tests(self):
        prev_sync_time = self._last_sync_time
        self._last_sync_time = datetime.now()

        # any new tests which come from a different worker which apply to the same binary
        new_tests = list(Test.unsynced_testcases(prev_sync_time)
                         .join(Job)
                         .where((Job.cs == self._cs) & (self._job.id != Job.id)))

        if new_tests:
            blobs = [str(t.blob) for t in new_tests]
            self._seen.update(blobs)
            self._fuzzer.pollenate(blobs)

        return len(new_tests)

    def _spawn_singlecb_fuzzer(self, path):
        add_extender = False
        cores = self._job.limit_cpu

        if self._job.limit_cpu >= 4:
            LOG.debug("4 or more cores specified, dedicating one to the extender")
            cores -= 1
            add_extender = True

        fzzr = fuzzer.Fuzzer(path, self._workdir, cores, create_dictionary=True)

        if add_extender:
            if not fzzr.add_extension('extender'):
                LOG.warning("Unable to spin-up the extender, using a normal AFL instance instead")
                fzzr.add_fuzzer()

        return fzzr

    def _spawn_multicb_fuzzer(self, paths):
        return fuzzer.Fuzzer(paths, self._workdir, self._job.limit_cpu, create_dictionary=True)

    def _spawn_fuzzer(self):

        if self._cs.is_multi_cbn:
            LOG.info("Challenge is a multicb, spinning up multiafl")
            self._fuzzer = self._spawn_multicb_fuzzer(self._cbn_paths)
        else:
            LOG.info("Challenge is a single cb, spinning up afl")
            self._fuzzer = self._spawn_singlecb_fuzzer(self._cbn_paths[0])

    def _start(self, job):
        """Run AFL with the specified number of cores."""
        self._timeout = job.limit_time

        LOG.info("Initializing fuzzer stats")
        fs = FuzzerStat.create(cs=self._cs)

        self._spawn_fuzzer()

        LOG.info("Created fuzzer for cs %s", job.cs.name)
        self._fuzzer.start()
        for _ in range(15):
            if self._fuzzer.alive:
                break
            time.sleep(1)
        else:
            raise Exception("Fuzzer failed to start")

        LOG.info("Started fuzzer")

        while self._timeout is None or self._runtime < self._timeout:
            time.sleep(5)
            self._runtime += 5

            LOG.debug("Updating fuzzer stats...")
            fs.pending_favs = int(self._fuzzer.stats['fuzzer-1']['pending_favs'])
            fs.pending_total = int(self._fuzzer.stats['fuzzer-1']['pending_total'])
            fs.paths_total = int(self._fuzzer.stats['fuzzer-1']['paths_total'])
            fs.paths_found = int(self._fuzzer.stats['fuzzer-1']['paths_found'])
            fs.last_path = datetime.fromtimestamp(int(self._fuzzer.stats['fuzzer-master']['last_path']))
            fs.save()

            LOG.debug("Checking results...")

            for c in self._fuzzer.crashes():
                self._check_crash(c)
            for c in self._fuzzer.queue():
                self._check_test(c)

            LOG.debug("Syncing new testcases...")
            n = self._sync_new_tests()
            if n > 0:
                LOG.debug("... synced %d new testcases!", n)

    def _run(self, job):
        self._cbn_paths = map(lambda cbn: cbn.path, self._cs.cbns_original)
        try:
            self._start(job)
        finally:
            if self._fuzzer is not None:
                self._fuzzer.kill()
