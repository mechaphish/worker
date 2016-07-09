#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import pickle

import tracer
from farnsworth.models import TracerCache, ChallengeBinaryNode

import worker.log
LOG = worker.log.LOG.getChild('workers')


class CRSTracerCacheManager(tracer.cachemanager.CacheManager):
    """CRSTracerCacheManager

    This class manages tracer caches for a given worker. Under-the-hood tracer
    will call into this code to both load and store caches.
    """
    def __init__(self):
        super(self.__class__, self).__init__()
        self.log = worker.log.LOG.getChild('cachemanager')
        self.cbn = None

    def cache_lookup(self):
        # Might better be a property?
        if self.cbn is not None:
            rdata = None
            try:
                cached = TracerCache.get(TracerCache.cbn == self.cbn)
                self.log.info("Loaded tracer state from cache for %s", self.cbn.name)
                return pickle.loads(str(cached.blob))
            except TracerCache.DoesNotExist:
                self.log.debug("No cached states found for %s", self.cbn.name)
        else:
            self.log.warning("cachemanager's cbn was never set, no cache to retrieve")

    def cacher(self, simstate):
        if self.cbn is not None:
            cache_data = self._prepare_cache_data(simstate)
            if cache_data is not None:
                self.log.info("Caching tracer state for challenge %s", self.cbn.name)
            TracerCache.create(cbn=self.cbn, blob=cache_data)
        else:
            self.log.warning("ChallengeBinaryNode was never set by 'set_cbn' cannot cache")


class Worker(object):
    def __init__(self):
        # Tracer cache set up for every job in case they use tracer
        self.tracer_cache = CRSTracerCacheManager()
        tracer.tracer.GlobalCacheManager = self.tracer_cache

        self._job = None
        self._cbn = None

    def _run(self, job):
        raise NotImplementedError("Worker must implement _run(self, job)")

    def run(self, job):
        # Set up job, cbn, and tracer cache
        self._job = job
        self._cbn = job.cbn
        self.tracer_cache.cbn = self._cbn

        self._run(job)
