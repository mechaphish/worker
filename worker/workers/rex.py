#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

import logging
import pickle

from farnsworth.models import Test, Exploit, RopCache
import rex
import tracer

from . import CRSTracerCacheManager
import worker.workers
LOG = worker.workers.LOG.getChild('rex')
LOG.setLevel('DEBUG')

logging.getLogger('rex').setLevel('INFO')


class RexWorker(worker.workers.Worker):

    def __init__(self):
        super(RexWorker, self).__init__()
        self._exploits = None
        self._crash = None
        self._crashing_test = None
        self._needs_retrace = False

    @staticmethod
    def _get_pov_score(exploit):
        return exploit.test_binary(enable_randomness=True, times=10).count(True) / 10.0

    def _save_exploit(self, exploit, crashing_test):
        LOG.info("Adding %s type %d", exploit.method_name, exploit.cgc_type)
        type_name = 'type%d' % exploit.cgc_type

        exploit = Exploit.create(cs=self._cs, job=self._job, pov_type=type_name,
                                 method=exploit.method_name, blob=exploit.dump_binary(),
                                 c_code=exploit.dump_c(), crash=crashing_test)

        return exploit

    def craft_leaks(self, crash):
        if not crash.leakable():
            LOG.error("Attempted to leak from a crash which cannot be leveraged for leaking")
            return

        try:
            for flag_leak in crash.point_to_flag():
                LOG.debug("Dumping possible leaking input to tests")
                test, created = Test.get_or_create(cs=self._cs, job=self._job, blob=flag_leak)
                if created:
                    LOG.debug("New flag leaking test id %d", test.id)
        except rex.CannotExploit:
            LOG.warning("Crash was leakable but was unable to point read at flag page")

    def forge_ahead(self, crashing_test, crash):
        while crash.explorable():
            # simultaneously explore and dump the new input into a file
            crash.explore("/tmp/new-testcase")

            # upload the new testcase
            Test.get_or_create(cs=self._cs, job=self._job, blob=open("/tmp/new-testcase").read())

            crashing_test.explored = True
            crashing_test.save()

            # dump a point-to-flag input if it's leakable
            if crash.leakable:
                self.craft_leaks(crash)

        return crash

    def exploit_crash(self, crashing_test, crash):
        e_pairs = [ ]
        for exploit in crash.yield_exploits():
            e_pairs.append((exploit, self._save_exploit(exploit, crashing_test)))

        crashing_test.exploited = True
        crashing_test.save()

        # safety loop, make sure we don't throw-away working exploits because of memory issues
        for exploit, e_db in e_pairs:
            e_db.reliability = 0.1 if exploit.test_binary() else 0.0
            e_db.save()

        # do this in a seperate loop to make sure we don't kill the worker before adding exploits
        for exploit, e_db in e_pairs:
            e_db.reliability = self._get_pov_score(exploit)
            e_db.save()

        # do we need to retrace without atoi hookups?
        if all([e.reliability == 0 for _, e in e_pairs]) and self._needs_retrace:
            self._needs_retrace = False

            self.tracer_cache = CRSTracerCacheManager(atoi_flag=False)
            self.tracer_cache.cs = self._cs
            tracer.tracer.GlobalCacheManager = self.tracer_cache

            LOG.warning("Exploit had 0 reliability with formated atoi info, rerunning without atoi info")
            self._run_rex()

    def _get_atoi_infos(self):
        """Run rex on the crashing testcase."""

        # Hook up atoi stuff
        atoi_infos = worker.workers.AtoiManager.get_atoi_info(self._cs.symbols)
        if len(atoi_infos) > 0:
            self._needs_retrace = True
            self.tracer_cache = CRSTracerCacheManager(atoi_flag=True)
            self.tracer_cache.cs = self._cs
            tracer.tracer.GlobalCacheManager = self.tracer_cache
            for a in atoi_infos:
                LOG.info("hooking %#x, %s", a.addr, a.func_name)
            LOG.info("Hooked up %d atoi infos", len(atoi_infos))
        else:
            LOG.debug("No atoi infos found")

        return atoi_infos

    def _run_rex(self, atoi_infos=None):

        LOG.info("Rex beginning to triage crash %d for cs %s", self._crashing_test.id, self._cs.name)

        try:
            cached_blob = str(RopCache.get(RopCache.cs == self._cs).blob)
            cached = pickle.loads(cached_blob)
            LOG.info("Got a rop cache")
        except RopCache.DoesNotExist:
            cached = None
            LOG.info("No rop cache available")

        use_rop = cached is not None
        crash = rex.Crash(self._cbn.path, str(self._crashing_test.blob), use_rop=use_rop,
                          rop_cache_tuple=cached, format_infos=atoi_infos)
        self._crash = crash

        if not crash.leakable() and not crash.exploitable() and not crash.explorable():
            raise ValueError("Crash was not exploitable or explorable")

        # split the crash in case we need to try both explore-for-exploit and forge-ahead
        forge_ahead_crash = crash.copy()

        try:
            # maybe we need to do some exploring first
            if forge_ahead_crash.leakable():
                LOG.info("Trying to leverage crash to cause a leak")
                self.craft_leaks(forge_ahead_crash)

            if forge_ahead_crash.explorable():
                LOG.info("Exploring crash in hopes of getting something more valuable")
                forge_ahead_crash = self.forge_ahead(self._crashing_test, forge_ahead_crash)

            if forge_ahead_crash.exploitable():
                LOG.info("Attempting to exploit crash")
                self.exploit_crash(self._crashing_test, forge_ahead_crash)

        except (rex.CannotExplore, rex.CannotExploit, rex.NonCrashingInput) as e:
            LOG.warning("Crash was not explorable using the forge-ahead method")
            LOG.error("Encountered error %s (%s)", e, e.message)

        # use explore-for-exploit
        if crash.one_of([rex.Vulnerability.WRITE_WHAT_WHERE, rex.Vulnerability.WRITE_X_WHERE]):
            self.exploit_crash(self._crashing_test, crash)

    def _start(self):

        atoi_infos = self._get_atoi_infos()

        if len(atoi_infos) == 0:
            atoi_infos = None

        self._run_rex(atoi_infos=atoi_infos)

    def _run(self, job):

        self._crashing_test = job.input_crash

        assert not self._cs.is_multi_cbn, "Rex can only be run on single cb challenge sets"

        try:
            self._start()
        except (rex.NonCrashingInput, rex.CannotExploit, ValueError, tracer.tracer.TracerMisfollowError) as e:
            job.input_crash.save()
            LOG.error(e)
        finally:
            # let everyone know this crash has been traced
            job._input_crash.triaged = True
            job._input_crash.save()
