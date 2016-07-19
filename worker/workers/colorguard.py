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

    @staticmethod
    def _get_pov_score(exploit):
        return exploit.test_binary(enable_randomness=True, times=10).count(True) / 10.0

    def _run(self, job):
        """Run colorguard on a testcase in an attempt to find leaks."""

        if self._cs.is_multi_cbn:
            LOG.warning("Colorguard scheduled on multicb, this is not yet supported")
            return

        LOG.debug("Invoking colorguard on challenge %s, testcase %s", self._cs.name, job.input_test.id)
        self._colorguard = colorguard.ColorGuard(self._cbn.path, str(job.input_test.blob))

        exploit = self._colorguard.attempt_exploit()
        if exploit is not None:
            LOG.info("Testcase %d causes a leak of the flag page", job.input_test.id)

            e = Exploit.create(cs=self._cs, job=self._job, pov_type="type2",
                           method=exploit.method_name, blob=exploit.dump_binary(),
                           c_code=exploit.dump_c())

            e.reliability = self._get_pov_score(exploit)

            LOG.info("Binary POV passed %d / 10 simulation tests", e.reliability * 10)

            e.save()

        else:
            LOG.debug("Unable to find leak or generate exploit for testcase")

        self._job.input_test.colorguard_traced = True
        self._job.input_test.save()
