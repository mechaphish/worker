#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

import worker.workers
LOG = worker.workers.LOG.getChild('povfuzzer1')
LOG.setLevel('DEBUG')


class PovFuzzer1Worker(worker.workers.VMWorker):
    def __init__(self):
        super(PovFuzzer1Worker, self).__init__()
        self._exploits = None
        self._crash = None

    def _start(self, job):
        """Runs PovFuzzer on the crashing testcase."""
        assert not self._cs.is_multi_cbn, "PovFuzzer1 can only be scheduled on single CBs for now"

        LOG.info("Pov fuzzer 1 about to try for job %d", job.id)
        LOG.info("Pov fuzzer 1 running ssh command")
        LOG.info("we should have %d cores", job.limit_cpu)
        self.execute("python /root/pov_fuzzing/main_type1.py %d" % job.id)

        crashing_test = job.input_crash

        LOG.info("Pov fuzzer 1 beginning to exploit crash %d for challenge %s", crashing_test.id, self._cs.name)
        pov_fuzzer = rex.pov_fuzzing.Type1CrashFuzzer(self._cbn.path, crash=str(crashing_test.blob))

        if not pov_fuzzer.exploitable():
            raise ValueError("Crash was not exploitable")

        LOG.info("crash was able to be exploited")
        Exploit.create(cs=self._cs, job=self._job, pov_type='type1',
                       method="type1fuzzer",
                       c_code=pov_fuzzer.dump_c(),
                       blob=pov_fuzzer.dump_binary())

    def _run(self, job):
        try:
            self._start(job)
        except (rex.CannotExploit, ValueError) as e:
            LOG.error(e)

