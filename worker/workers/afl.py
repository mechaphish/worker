#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import datetime
import time

from farnsworth.models import (Bitmap, ChallengeBinaryNode, Crash, FuzzerStat,
                               Job, Test)
import fuzzer
import rex

import worker.workers
LOG = worker.workers.LOG.getChild('afl')
LOG.setLevel('DEBUG')


class AFLWorker(worker.workers.Worker):
    def __init__(self):
        super(AFLWorker, self).__init__()
        self._workername = 'afl'
        self._seen = set()
        self._workdir = '/dev/shm/work'
        self._fuzzer = None
        self._runtime = 0
        self._timeout = None
        self._last_bm = None
        self._last_sync_time = datetime.datetime.now()

    def _update_bitmap(self):
        bm = self._fuzzer.bitmap()

        if self._last_bm == bm:
            return
        else:
            self._last_bm = bm

        dbm = self._cbn.bitmap.first()
        if dbm is not None:
            dbm.blob = bm
        else: #except Bitmap.DoesNotExist: #pylint:disable=no-member
            dbm = Bitmap(blob=bm, cbn=self._cbn)
        dbm.save()

    def _check_test(self, t):
        if t in self._seen: return
        self._seen.add(t)

        LOG.info("Got test of length %s", len(t))
        self._job.produced_output = True
        self._update_bitmap()
        t = Test.create(cbn=self._cbn, job=self._job, blob=t, drilled=False)

    def _check_crash(self, t):
        if t in self._seen: return
        self._seen.add(t)

        LOG.info("Got crash of length %s", len(t))
        self._job.produced_output = True
        self._update_bitmap()
        try:
            crash_kind = rex.Crash.quick_triage(self._cbn.path, t)
        except Exception as e:  # pylint: disable=broad-except
            LOG.error("Received a %s exception, shouldn't happen", str(e))
            crash_kind = None

        if crash_kind is None:
            LOG.error("Encountered crash_kind of None, this shouldn't happen")
            LOG.error("Binary: %s", self._cbn.path)
            LOG.error("Crash: %s", t.encode('hex'))
            return

        Crash.create(cbn=self._cbn, job=self._job, blob=t, drilled=False, kind=crash_kind)

    def _sync_new_tests(self):
        prev_sync_time = self._last_sync_time
        self._last_sync_time = datetime.datetime.now()

        # any new tests which come from a different worker which apply to the same binary
        new_tests = list(Test.unsynced_testcases(prev_sync_time)
                         .join(Job).where(Job != self._job)
                         .join(ChallengeBinaryNode)
                         .where(ChallengeBinaryNode == self._cbn))

        if new_tests:
            blobs = [str(t.blob) for t in new_tests]
            self._seen.update(blobs)
            self._fuzzer.pollenate(blobs)

        return len(new_tests)

    def _start(self, job):
        """Run AFL with the specified number of cores."""

        self._job = job
        self._cbn = job.cbn
        self._timeout = job.limit_time

        # first, get the seeds we currently have, for the entire CB, not just for this binary
        all_tests = list(self._cbn.tests)
        if all_tests:
            self._seen.update(str(t.blob) for t in all_tests)

        LOG.info("Initializing fuzzer stats")
        fs = FuzzerStat.create(cbn=self._cbn)

        self._fuzzer = fuzzer.Fuzzer(self._cbn.path, self._workdir,
                                     self._job.limit_cpu, seeds=self._seen,
                                     create_dictionary=True)

        LOG.info("Created fuzzer for cbn %s", job.cbn.id)
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
            fs.last_path = datetime.datetime.fromtimestamp(int(self._fuzzer.stats['fuzzer-master']['last_path']))
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
        try:
            self._start(job)
        finally:
            if self._fuzzer is not None:
                self._fuzzer.kill()
