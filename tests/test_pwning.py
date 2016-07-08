#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import os
import time
import threading

import dotenv
dotenv.load_dotenv(os.path.join(os.path.dirname(__file__), '../../farnsworth/.env'))

from farnsworth.models import (ChallengeSet, ChallengeBinaryNode, AFLJob,
                               DrillerJob, RexJob, Test, Crash, Exploit)

import worker

class AFLThread(threading.Thread):
    def __init__(self, job):
        super(AFLThread, self).__init__()
        self._job = job
        self._worker = None

    def run(self):
        self._worker = worker.workers.AFLWorker()
        self._worker.run(self._job)


def try_drilling(name, get_crashes):
    # set up the node
    cs = ChallengeSet.get_or_create(name=name.split('_')[0])
    cbn = ChallengeBinaryNode.get_create(name=name, cs=cs)
    cbn.root = cbn
    cbn.save()

    Exploit.delete().where(Exploit.cbn == cbn).execute()

    if not cbn.crashes or get_crashes:
        # Delete the testcases
        Test.delete().where(Test.cbn == cbn).execute()
        Crash.delete().where(Crash.cbn == cbn).execute()

        assert len(cbn.tests) == 0

        afl_job = AFLJob.create(cbn=cbn, limit_cpu=4, limit_memory=1, limit_time=80)
        afl_thread = AFLThread(afl_job)
        afl_thread.start()

        for _ in range(10):
            if len(cbn.tests) == 2: break
            time.sleep(1)
        assert len(cbn.tests) == 2
        assert len(afl_thread._worker._seen) == 2
        assert len(cbn.crashes) == 0

        # schedule driller
        for i in cbn.tests:
            dj = DrillerJob.create(payload=i, cbn=cbn, limit_cpu=1, limit_memory=10)
            dw = worker.DrillerWorker()
            dw.run(dj)

            assert len(dj.tests) > 0 #pylint:disable=no-member

        for _ in range(80):
            if len(cbn.crashes) > 0: break
            time.sleep(1)
        assert len(afl_thread._worker._seen) > 2
        assert len(cbn.tests) > 2
        assert len(cbn.crashes) > 0

        afl_thread.join()

    sorted_crashes = sorted(cbn.crashes, key=lambda x: -len(str(x.blob)))
    print "Chose crash of length %d" % len(sorted_crashes[0].blob)

    rj = RexJob.create(payload=sorted_crashes[0], cbn=cbn, limit_cpu=1, limit_memory=10)
    rw = worker.RexWorker()
    rw.run(rj)

    assert len(cbn.exploits) == 2

def test_pwning():
    try_drilling('00000201_01', True)

if __name__ == '__main__':
    #try_drilling('00000201_01', False)
    try_drilling('00000201_01', True)
