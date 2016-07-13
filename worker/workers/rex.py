#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

from farnsworth.models import Test, Exploit, RopCache
import rex
import pickle
import tracer

import worker.workers
LOG = worker.workers.LOG.getChild('rex')
LOG.setLevel('DEBUG')


class RexWorker(worker.workers.Worker):
    def __init__(self):
        super(RexWorker, self).__init__()
        self._exploits = None
        self._crash = None

    @staticmethod
    def _get_pov_score(exploit):
        return exploit.test_binary(enable_randomness=True, times=10).count(True) / 10.0

    def _save_exploit(self, exploit):
        LOG.info("Adding %s type %d", exploit.method_name, exploit.cgc_type)
        type_name = 'type%d' % exploit.cgc_type

        exploit = Exploit.create(cbn=self._cbn, job=self._job, pov_type=type_name,
                                 method=exploit.method_name, blob=exploit.dump_binary(),
                                 c_code=exploit.dump_c())
        self._cbn.save()
        return exploit

    def _start(self, job):
        """Run rex on the crashing testcase."""

        crashing_test = job.input_crash

        try:
            cached_blob = str(RopCache.get(RopCache.cbn == self._cbn).blob)
            cached = pickle.loads(cached_blob)
            LOG.info("got a rop cache")
        except RopCache.DoesNotExist:
            cached = None
            LOG.info("no rop cache available")

        LOG.info("Rex beginning to triage crash %d for cbn %d", crashing_test.id, self._cbn.id)

        use_rop = cached is not None
        crash = rex.Crash(self._cbn.path, str(crashing_test.blob), use_rop=use_rop, rop_cache_tuple=cached)
        self._crash = crash

        if not crash.exploitable() and not crash.explorable():
            raise ValueError("Crash was not exploitable or explorable")

        if crash.crash_type in [rex.Vulnerability.ARBITRARY_READ]:
            try:
                # attempt to create a testcase which will leak the flag
                # colorguard will trace this later
                flag_leak = crash.point_to_flag()

                Test.create(cbn=self._cbn, job=self._job, blob=flag_leak)
            except rex.CannotExploit:
                LOG.warning("Crash was an arbitrary-read but was unable to point read at flag page")

        # maybe we need to do some exploring first
        while crash.explorable():
            LOG.info("Exploring crash in hopes of getting something more valuable")

            # simultaneously explore and dump the new input into a file
            crash.explore("/tmp/new-testcase")

            # upload the new testcase
            # FIXME: we probably want to store it in a different table with custom attrs
            Test.create(cbn=self._cbn, job=self._job, blob=open("/tmp/new-testcase").read())

        # see if we can immiediately begin exploring the crash
        e_pairs = [ ]
        for exploit in crash.yield_exploits():
            e_pairs.append((exploit, self._save_exploit(exploit)))

        # do this in a seperate loop to make sure we don't kill the worker before adding exploits
        for exploit, e_db in e_pairs:
            e_db.reliability = self._get_pov_score(exploit)
            e_db.save()

        # let everyone know this crash has been traced
        crashing_test.triaged = True
        crashing_test.save()

    def _run(self, job):
        try:
            self._start(job)
        except (rex.NonCrashingInput, rex.CannotExploit, ValueError, tracer.tracer.TracerMisfollowError) as e:
            job.input_crash.explorable = False
            job.input_crash.exploitable = False
            job.input_crash.save()
            # FIXME: log exception somewhere
            LOG.error(e)
