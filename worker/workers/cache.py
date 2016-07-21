#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import logging

import tracer
from rex.trace_additions import ZenPlugin

import worker.workers
LOG = worker.workers.LOG.getChild('cache')
LOG.setLevel('INFO')

logging.getLogger("tracer").setLevel("INFO")


class CacheWorker(worker.workers.Worker):

    def __init__(self):
        super(CacheWorker, self).__init__()

    def _run(self, job):
        """Create a cache"""
        assert not job.cs.is_multi_cbn, "CacheWorker scheduled on multicb, this should NOT happen"

        LOG.debug("Invoking cache worker on challenge %s", self._cs.name)

        # Run until the first receive
        tr = tracer.Tracer(self._cbn.path, str(""))

        # Enable the ZenPlugin
        ZenPlugin.prep_tracer(tr)

        tr.run()
