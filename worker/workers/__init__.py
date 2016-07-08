#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import worker.log

LOG = worker.log.LOG.getChild('workers')
CMLOG = worker.log.LOG.getChild('cachemanager')

import pickle
import tracer
from tracer import tracer as tracerfile
from farnsworth.models import TracerCache, ChallengeBinaryNode

class CRSTracerCacheManager(tracer.cachemanager.CacheManager):
    """
    CRSTracerCacheManager
    This class manages tracer caches for a given worker.
    Under-the-hood tracer will call into this code to both load
    and store caches.
    """

    def __init__(self):
        super(CRSTracerCacheManager, self).__init__()

        self._cbn = None

    def set_cbn(self, cbn):
        self._cbn = cbn

    def cache_lookup(self):

        if self._cbn is not None:
            rdata = None
            tquery = TracerCache.select().join(ChallengeBinaryNode).\
                    where(ChallengeBinaryNode.id == self._cbn.id) # pylint:disable=no-member

            if tquery.exists():
                CMLOG.info("loading tracer state from cache")
                tc = tquery.get()
                rdata = pickle.loads(str(tc.blob))

            return rdata
        else:
            CMLOG.warning("cachemanager's cbn was never set, no cache to retrieve")

    def cacher(self):

        if self._cbn is not None:
            cdata = self._prepare_cache_data()
            if cdata is not None:
                CMLOG.info("caching tracer state for challenge %s", self._cbn.name)

            TracerCache.create(cbn=self._cbn, blob=cdata)

        else:
            CMLOG.warning("ChallengeBinaryNode never set by `set_cbn` can't cache")

class Worker(object):

    def __init__(self):

        # tracer cache set up for every job in case they use tracer
        self.tcacher = CRSTracerCacheManager()
        tracerfile.GlobalCacheManager = self.tcacher

        self._job = None
        self._cbn = None

    def _run(self, job):
        raise NotImplementedError

    def run(self, job):

        # set up job, cbn, and tracer cache
        self._job = job
        self._cbn = job.cbn

        self.tcacher.set_cbn(self._cbn)

        self._run(job)
