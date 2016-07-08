#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

from farnsworth.models import Exploit
import rex.pov_fuzzing

import worker.workers
LOG = worker.workers.LOG.getChild('povfuzzer1')
LOG.setLevel('DEBUG')


class PovFuzzer1Worker(worker.workers.Worker):
    def __init__(self):
        super(PovFuzzer1Worker, self).__init__()
        self._exploits = None
        self._crash = None

    def _start(self, job):
        """
        Runs PovFuzzer on the crashing testcase.
        """

        # TODO: handle the possibility of a job submitting a PoV, rex already supports this
        crashing_test = job.input_crash

        LOG.info("Pov fuzzer 1 beginning to exploit crash %d for cbn %d", crashing_test.id, self._cbn.id)

        pov_fuzzer = rex.pov_fuzzing.Type1CrashFuzzer(self._cbn.path, crash=str(crashing_test.blob))

        if not pov_fuzzer.exploitable():
            raise ValueError("Crash was not exploitable")

        LOG.info("crash was able to be exploited")

        Exploit.create(cbn=self._cbn, job=self._job, pov_type='type1',
                       exploitation_method="type1fuzzer",
                       blob=pov_fuzzer.dump_binary())

    def _run(self, job):
        try:
            self._start(job)
        except (rex.CannotExploit, ValueError) as e:
            job.input_crash.exploitable = False
            job.input_crash.save()
            # FIXME: log exception somewhere
            LOG.error(e)
