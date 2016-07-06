#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""Generate simple IDS rules from Jacopo's examples."""

from __future__ import unicode_literals, absolute_import

import worker.workers
LOG = worker.workers.LOG.getChild('function_identifier')
LOG.setLevel('DEBUG')


class FunctionIdentifierWorker(worker.workers.Worker):
    """Generate simple identities for functions, will be used to hook up simprocedues."""
    def __init__(self):
        self._job = None
        self._cbn = None

    def run(self, job):
        self._job = job
        self._cbn = job.cbn
        # TODO enfore time limit

        project = angr.Project(self._cbn.path)
        LOG.info("Inititalizing Identifier")
        idfer = identifier.Identifier(project)

        LOG.info("Identifier initialized running...")

        for addr, symbol in idfer.run():
            LOG.debug("Identified %s at %#x", symbol, addr)
            FunctionIdentity.create(cbn=self._cbn, address=addr, symbol=symbol)

        LOG.debug("Idenitified a total of %d functions", len(idfer.matches))
        LOG.info("Done identifying functions for challenge %s", self._cbn.name)
