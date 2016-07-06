#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

from farnsworth.models import Test, Exploit
import rex
import tracer

import worker.workers
LOG = worker.workers.LOG.getChild('rex')
LOG.setLevel('DEBUG')


class RexWorker(worker.workers.Worker):
    def __init__(self):
        self._job = None
        self._cbn = None
        self._exploits = None
        self._crash = None

    def _run(self, job):
        """Run rex on the crashing testcase."""
        self._job = job
        self._cbn = job.cbn

        crashing_test = job.input_crash

        LOG.info("Rex beginning to triage crash %d for cbn %d", crashing_test.id, self._cbn.id)

        crash = rex.Crash(self._cbn.path, str(crashing_test.blob))
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
                LOG.warning('crash was an arbitrary-read but was unable to point read at flag page')

        # maybe we need to do some exploring first
        while crash.explorable():
            LOG.info("exploring crash in hopes of getting something more valuable")

            # simultaneously explore and dump the new input into a file
            crash.explore('/tmp/new-testcase')

            # upload the new testcase
            # FIXME: we probably want to store it in a different table with custom attrs
            Test.create(cbn=self._cbn, job=self._job, blob=open('/tmp/new-testcase').read())

        # see if we can immiediately begin exploring the crash
        exploits = crash.exploit()
        self._exploits = exploits

        if exploits.best_type1 is None and exploits.best_type2 is None:
            LOG.error("crash had symptoms of exploitability, but no exploits could be built")

        LOG.info("crash was able to be exploited")
        LOG.debug("can set %d registers with type-1 exploits", len(exploits.register_setters))
        LOG.debug("generated %d type-2 exploits", len(exploits.leakers))
        # return (type1 exploit, type2 exploit), none if they don't exist

        for exploit in exploits.register_setters:

            LOG.info("Adding %s type 1!", exploit.method_name)
            Exploit.create(cbn=self._cbn, job=self._job, pov_type='type1',
                           exploitation_method=exploit.method_name,
                           blob=exploits.best_type1.dump_binary())
            self._cbn.save()

        for exploit in exploits.leakers:
            LOG.info("Adding %s type 2!", exploit.method_name)
            Exploit.create(cbn=self._cbn, job=self._job, pov_type='type2',
                           exploitation_method=exploit.method_name,
                           blob=exploits.best_type2.dump_binary())

        # let everyone know this crash has been traced
        crashing_test.triaged = True
        crashing_test.save()

    def run(self, job):
        try:
            self._run(job)
        except (rex.CannotExploit, ValueError, tracer.tracer.TracerMisfollowError) as e:
            job.input_crash.explorable = False
            job.input_crash.exploitable = False
            job.input_crash.save()
            # FIXME: log exception somewhere
            LOG.error(e)
