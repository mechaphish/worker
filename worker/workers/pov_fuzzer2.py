#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

from farnsworth.models import Test, Exploit
import rex.pov_fuzzing

import worker.workers
LOG = worker.workers.LOG.getChild('povfuzzer2')
LOG.setLevel('DEBUG')


class PovFuzzer2Worker(worker.workers.Worker):
    def __init__(self):
        super(PovFuzzer2Worker, self).__init__()
        self._exploits = None
        self._crash = None

    def _start(self, job):
        """
        Runs PovFuzzer on the crashing testcase.
        """

        # TODO: handle the possibility of a job submitting a PoV, rex already supports this
        crashing_test = job.input_crash

        LOG.info("Pov fuzzer 2 beginning to exploit crash %d for cbn %d", crashing_test.id, self._cbn.id)

        pov_fuzzer = rex.pov_fuzzing.Type2CrashFuzzer(self._cbn.path, crash=str(crashing_test.blob))

        if pov_fuzzer.exploitable():
            Exploit.create(cbn=self._cbn, job=self._job, pov_type='type1',
                           exploitation_method="type1fuzzer",
                           blob=pov_fuzzer.dump_binary())
            LOG.info("crash was able to be exploited")
        else:
            LOG.warning("Not exploitable")

        if pov_fuzzer.dumpable():
            # FIXME: we probably want to store it in a different table with custom attrs
            Test.create(cbn=self._cbn, job=self._job, blob=pov_fuzzer.get_leaking_payload())
            LOG.info("possible leaking test was created")
        else:
            LOG.warning("Couldn't even dump a leaking input")

    def _run(self, job):
        try:
            self._start(job)
        except (rex.CannotExploit, ValueError) as e:
            job.input_crash.exploitable = False
            job.input_crash.save()
            # FIXME: log exception somewhere
            LOG.error(e)
