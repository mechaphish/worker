#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

import logging

import colorguard
from farnsworth.models import Exploit

import worker.workers
LOG = worker.workers.LOG.getChild('colorguard')
LOG.setLevel('DEBUG')

# Let's look at the output of POV testing, because it's been known to have bugs
logging.getLogger('colorguard').setLevel("DEBUG")


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

        LOG.debug("Invoking colorguard on cbn %s, testcase %s", job.cbn.id, job.input_test.id)
        self._colorguard = colorguard.ColorGuard(self._cbn.path, str(job.input_test.blob))

        exploit = self._colorguard.attempt_exploit()
        if exploit is not None:
            LOG.info("Testcase %d causes a leak of the flag page", job.input_test.id)

            if exploit.test_binary():
                LOG.info("Binary POV passed simulation tests!")
            else:
                LOG.error("ColorGuard created POV for Testcase %d, but if failed!", job.input_test.id)

            Exploit.create(cbn=self._cbn, job=self._job, pov_type="type2",
                           exploitation_method=exploit.method_name,
                           blob=exploit.dump_binary())
        else:
            LOG.debug("Unable to find leak or generate exploit for testcase")

        self._job.input_test.colorguard_traced = True
        self._job.input_test.save()
