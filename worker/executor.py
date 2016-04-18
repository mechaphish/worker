import os
import time
import timeout_decorator

import workers
from farnsworth.models import Job, AFLJob, DrillerJob, RexJob

class Executor(object):
    def __init__(self, job_id, tries=5):
        self.job_id = job_id
        self.job = Job.find(job_id)
        self.tries = tries
        self.work = None

    def run(self):
        while self.tries > 0:
            if self.job is not None:
                print "[Worker] Running job %s" % self.job_id
                if self.job.worker == 'afl':
                    self.job = AFLJob.find(self.job_id) # FIXME
                    self.work = workers.AFLWorker()
                elif self.job.worker == 'rex':
                    self.job = RexJob.find(self.job_id) # FIXME
                    self.work = workers.RexWorker()
                elif self.job.worker == 'driller':
                    self.job = DrillerJob.find(self.job_id) # FIXME
                    self.work = workers.DrillerWorker()
                elif self.job.worker == 'patcherex':
                    self.work = workers.PatcherexWorker()

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
