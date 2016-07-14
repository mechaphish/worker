#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import logging
import pickle


import angr
import angrop  # pylint: disable=unused-import

from farnsworth.models import RopCache

import worker.workers
LOG = worker.workers.LOG.getChild('rop_cache')
LOG.setLevel('INFO')


class RopCacheWorker(worker.workers.Worker):

    def __init__(self):
        super(RopCacheWorker, self).__init__()

    def _run(self, job):
        """Create a rop cache"""

        # make angrop cache
        proj = angr.Project(self._cbn.path)
        rop = proj.analyses.ROP()
        rop.find_gadgets_single_threaded()
        cache_data = pickle.dumps(rop._get_cache_tuple(),
                                  pickle.HIGHEST_PROTOCOL)
        RopCache.create(cbn=self._cbn, blob=cache_data)
