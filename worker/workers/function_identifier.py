#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""Generate simple IDS rules from Jacopo's examples."""

from __future__ import unicode_literals, absolute_import

import angr
from farnsworth.models import FunctionIdentity
import identifier
import cPickle as pickle

import worker.workers
LOG = worker.workers.LOG.getChild('function_identifier')
LOG.setLevel('DEBUG')


class FunctionIdentifierWorker(worker.workers.Worker):
    """Generate simple identities for functions, will be used to hook up simprocedues."""
    def __init__(self):
        super(FunctionIdentifierWorker, self).__init__()

    def _run(self, job):

        assert not self._cs.is_multi_cbn, "FunctionIdentifier can only be scheduled for single CBs"

        project = angr.Project(self._cbn.path)
        LOG.info("Inititalizing Identifier")
        idfer = identifier.Identifier(project)

        LOG.info("Initialized, populating function infos")
        for f, info in idfer.func_info.items():
            pd = pickle.dumps(info)
            FunctionIdentity.create(cs=self._cs, address=f.addr, func_info=pd)

        LOG.info("Now running identifier...")

        for addr, symbol in idfer.run():
            LOG.debug("Identified %s at %#x", symbol, addr)
            fi, _  = FunctionIdentity.get_or_create(cs=self._cs, address=addr)
            fi.symbol = symbol
            fi.save()

        LOG.debug("Idenitified a total of %d functions", len(idfer.matches))
        LOG.info("Done identifying functions for challenge %s", self._cs.name)
