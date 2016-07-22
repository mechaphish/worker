#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""Create PatchPerformance Result from Test Results"""

from __future__ import absolute_import, unicode_literals

import os

from patch_performance import compute_patch_performance
from farnsworth.models import PatchPerformanceJob

import worker.workers
LOG = worker.workers.LOG.getChild('patch_performance')
LOG.setLevel('DEBUG')


class PatchPerformanceWorker(worker.workers.Worker):
    """Create PatchPerformance Result from Test Results."""

    def __init__(self):
        super(self.__class__, self).__init__()

    def _run(self, job):
        assert isinstance(job, PatchPerformanceJob)

        target_cs = job.cs
        if target_cs is not None:
            LOG.info("Trying to compute aggregate performance for CS %s", target_cs.name)
            compute_patch_performance(target_cs)
            LOG.info("Computed Aggregate performance for CS %s", target_cs.name)
