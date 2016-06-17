from ..worker import Worker
from farnsworth.models import Exploit
import colorguard

import logging
l = logging.getLogger('crs.worker.workers.colorguard_worker')
l.setLevel("DEBUG")

class ColorGuardWorker(Worker):
    def __init__(self):
        self._seen = set()
        self._colorguard = None
        self._job = None
        self._cbn = None
        self._seen = set()

    def run(self, job):
        '''
        Drills a testcase.
        '''

        self._job = job
        self._cbn = job.cbn
        self._job.input_test.colorguard_traced = True
        self._job.input_test.save()

        self._colorguard = colorguard.ColorGuard(self._cbn.path, str(job.input_test.blob))

        if self._colorguard.causes_leak():
            l.info('Testcase %d causes a leak of the flag page', job.input_test.id)

            exploit = self._colorguard.attempt_pov()
            if not exploit.test_binary():
                l.error("ColorGuard created POV for Testcase %d, but if failed!", job.input_test.id)

            Exploit.create(cbn=self._cbn, job=self._job, pov_type='type2', blob=exploit.dump_binary())
