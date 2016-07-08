#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import driller
from farnsworth.models import Test
from simuvex.procedures import SimProcedures

import worker.workers
LOG = worker.workers.LOG.getChild('driller')
LOG.setLevel('INFO')

import logging
logging.getLogger("driller").setLevel("INFO")

class DrillerWorker(worker.workers.Worker):
    DONT_HOOK = ["malloc", "free", "realloc", "printf", "snprintf"]

    def __init__(self):
        super(DrillerWorker, self).__init__()
        self._seen = set()
        self._driller = None
        self._seen = set()

    def _run(self, job):
        """Drill a testcase."""
        self._job = job
        self._cbn = job.cbn

        hooks = dict()
        for addr, symbol in self._cbn.symbols.items():
            if symbol in self.DONT_HOOK:
                continue

            if symbol in SimProcedures['libc.so.6']:
                LOG.info("Hooking up %#x -> %s", addr, symbol)
                hooks[addr] = SimProcedures['libc.so.6'][symbol]

        LOG.info("Hooked up %d addresses to simprocedures", len(hooks))

        self._driller = driller.Driller(self._cbn.path, job.input_test.blob,
                                        self._cbn.bitmap.first().blob, 'tag',
                                        hooks=hooks)

        for _, t in self._driller.drill_generator():
            if t in self._seen:
                continue
            self._seen.add(t)

            LOG.info("Found new testcase (of length %s)!", len(t))
            Test.create(cbn=self._cbn, job=self._job, blob=t)

        self._job.input_test.drilled = True
        self._job.input_test.save()
