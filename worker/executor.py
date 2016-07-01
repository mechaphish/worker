import os
import time
import timeout_decorator

import workers
from farnsworth.models import (
    Job,
    AFLJob,
    ColorGuardJob,
    DrillerJob,
    IDSJob,
    NetworkPollJob,
    PatcherexJob,
    PovFuzzer1Job,
    PovFuzzer2Job,
    RexJob,
    WereRabbitJob,
    to_job_type
)


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
                print "[Worker] Running job %s %s" % (self.job_id,
                                                      self.__class__.__name__)
                if isinstance(self.job, AFLJob):
                    self.work = workers.AFLWorker()
                elif isinstance(self.job, ColorGuardJob):
                    self.work = workers.ColorGuardWorker()
                elif isinstance(self.job, DrillerJob):
                    self.work = workers.DrillerWorker()
                elif isinstance(self.job, IDSJob):
                    self.work = workers.IDSWorker()
                elif isinstance(self.job, NetworkPollJob):
                    self.work = workers.NetworkPollWorker()
                elif isinstance(self.job, PatcherexJob):
                    self.work = workers.PatcherexWorker()
                elif isinstance(self.job, PovFuzzer1Job):
                    self.work = workers.PovFuzzer1Worker()
                elif isinstance(self.job, PovFuzzer2Job):
                    self.work = workers.PovFuzzer2Worker()
                elif isinstance(self.job, RexJob):
                    self.work = workers.RexWorker()
                elif isinstance(self.job, WereRabbitJob):
                    self.work = workers.WereRabbitWorker()

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
            @timeout_decorator.timeout(self.job.limit_time, use_signals=True)
            def _timeout_run():
                self.work.run(self.job)
            try:
                _timeout_run()
            except timeout_decorator.TimeoutError:
                print "[Worker] Job execution timeout!"
        else:
            self.work.run(self.job)

        self.job.completed()
        self.job.produced_output = True
        self.job.save()
