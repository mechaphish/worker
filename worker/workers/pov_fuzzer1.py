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

    def _run(self, job):
        try:
            self._start(job)
        except ValueError as e:
            job.input_crash.exploitable = False
            job.input_crash.save()
            LOG.error(e)

