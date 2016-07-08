#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

# let's look at the output of POV testing, because it's been known to have bugs
import logging
logging.getLogger('rex').setLevel("DEBUG")

import colorguard
from farnsworth.models import Exploit

import worker.workers
LOG = worker.workers.LOG.getChild('colorguard')
LOG.setLevel('DEBUG')


class ColorGuardWorker(worker.workers.Worker):
    def __init__(self):
        super(ColorGuardWorker, self).__init__()
        self._seen = set()
        self._colorguard = None
        self._seen = set()

    def _run(self, job):
        """Run colorguard on a testcase in an attempt to find leaks."""

        self._job = job
        self._cbn = job.cbn

        LOG.debug('Invoking colorguard on cbn %s, testcase %s', job.cbn.id, job.input_test.id)
        self._colorguard = colorguard.ColorGuard(self._cbn.path, str(job.input_test.blob))

        if self._colorguard.causes_leak():
            LOG.info('Testcase %d causes a leak of the flag page', job.input_test.id)

            exploit = self._colorguard.attempt_pov()
            if exploit.test_binary():
                LOG.info('Binary POV passed simulation tests!')
            else:
                LOG.error('ColorGuard created POV for Testcase %d, but if failed!', job.input_test.id)

            Exploit.create(cbn=self._cbn, job=self._job, pov_type='type2',
                           exploitation_method=exploit.method_name,
                           blob=exploit.dump_binary())

        self._job.input_test.colorguard_traced = True
        self._job.input_test.save()
