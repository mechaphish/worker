#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import time

import stopit

# Import settings before everything else
import worker.settings

from farnsworth.models import (to_job_type, Job, AFLJob, BackdoorSubmitterJob,
                               CacheJob, ColorGuardJob, DrillerJob,
                               FunctionIdentifierJob, IDSJob, NetworkPollCreatorJob,
                               PatcherexJob, PatchPerformanceJob, PovFuzzer1Job,
                               PovFuzzer2Job, RexJob, RopCacheJob,
                               ShowmapSyncJob, TesterJob)

from .workers.afl import AFLWorker
from .workers.backdoor import BackdoorSubmitterWorker
from .workers.cache import CacheWorker
from .workers.colorguard import ColorGuardWorker
from .workers.driller import DrillerWorker
from .workers.function_identifier import FunctionIdentifierWorker
from .workers.ids import IDSWorker
from .workers.network_poll_creator import NetworkPollCreatorWorker
from .workers.patcherex import PatcherexWorker
from .workers.patch_performance import PatchPerformanceWorker
from .workers.pov_fuzzer1 import PovFuzzer1Worker
from .workers.pov_fuzzer2 import PovFuzzer2Worker
from .workers.rex import RexWorker
from .workers.rop_cache import RopCacheWorker
from .workers.showmap_sync import ShowmapSyncWorker
from .workers.tester import TesterWorker


class Executor(object):
    def __init__(self, job_id, tries=5):
        self.job_id = job_id
        self.job = Job.find(job_id)
        self.tries = tries
        self.work = None

    def run(self):
        while self.tries > 0:
            if self.job is not None:
                self.job = to_job_type(self.job)
                print "[Worker] Running job %s (class: %s)" % (self.job_id,
                                                               self.job.__class__.__name__)
                if isinstance(self.job, AFLJob):
                    self.work = AFLWorker()
                elif isinstance(self.job, BackdoorSubmitterJob):
                    self.work = BackdoorSubmitterWorker()
                elif isinstance(self.job, CacheJob):
                    self.work = CacheWorker()
                elif isinstance(self.job, ColorGuardJob):
                    self.work = ColorGuardWorker()
                elif isinstance(self.job, DrillerJob):
                    self.work = DrillerWorker()
                elif isinstance(self.job, FunctionIdentifierJob):
                    self.work = FunctionIdentifierWorker()
                elif isinstance(self.job, IDSJob):
                    self.work = IDSWorker()
                elif isinstance(self.job, NetworkPollCreatorJob):
                    self.work = NetworkPollCreatorWorker()
                elif isinstance(self.job, PatcherexJob):
                    self.work = PatcherexWorker()
                elif isinstance(self.job, PatchPerformanceJob):
                    self.work = PatchPerformanceWorker()
                elif isinstance(self.job, PovFuzzer1Job):
                    self.work = PovFuzzer1Worker()
                elif isinstance(self.job, PovFuzzer2Job):
                    self.work = PovFuzzer2Worker()
                elif isinstance(self.job, RexJob):
                    self.work = RexWorker()
                elif isinstance(self.job, RopCacheJob):
                    self.work = RopCacheWorker()
                elif isinstance(self.job, ShowmapSyncJob):
                    self.work = ShowmapSyncWorker()
                elif isinstance(self.job, TesterJob):
                    self.work = TesterWorker()

                self._timed_execution()
                print "[Worker] Done job #%s" % self.job_id
                return self.job

            print "[Worker] Waiting for job %s, #%s" % (self.job_id, self.tries)
            self.tries -= 1
            time.sleep(3)

        print "[Worker] Job #%s not found" % self.job_id

    def _timed_execution(self):
        self.job.started()

        if self.job.limit_time is not None:
            try:
                with stopit.SignalTimeout(self.job.limit_time, swallow_exc=False):
                    self.work.run(self.job)
            except stopit.TimeoutException:
                print "[Worker] Job execution timeout!"
        else:
            self.work.run(self.job)

        self.job.completed()
        self.job.produced_output = True
        self.job.save()
