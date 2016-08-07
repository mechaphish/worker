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

        LOG.info("Pov fuzzer 1 about to try for job %d", job.id)
        LOG.info("Pov fuzzer 1 running ssh command")
        LOG.info("we should have %d cores", job.limit_cpu)
        self.execute("python /root/pov_fuzzing/main_type1.py %d" % job.id)

    def _run(self, job):
        self._start(job)
