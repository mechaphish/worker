from ..worker import Worker
from farnsworth.models import Exploit
import colorguard

import logging
l = logging.getLogger('crs.worker.workers.colorguard_worker')
l.setLevel("DEBUG")

# let's look at the output of POV testing, because it's been known to have bugs
logging.getLogger('rex').setLevel("DEBUG")

class ColorGuardWorker(Worker):
    def __init__(self):
        self._seen = set()
        self._colorguard = None
        self._job = None
        self._cbn = None
        self._seen = set()

    def run(self, job):
        '''
        Runs colorguard on a testcase in an attempt to find leaks.
        '''

        self._job = job
        self._cbn = job.cbn
        self._job.input_test.colorguard_traced = True
        self._job.input_test.save()

        l.debug('Invoking colorguard on cbn %s, testcase %s', job.cbn.id, job.input_test.id)
        self._colorguard = colorguard.ColorGuard(self._cbn.path, str(job.input_test.blob))

        if self._colorguard.causes_leak():
            l.info('Testcase %d causes a leak of the flag page', job.input_test.id)

            exploit = self._colorguard.attempt_pov()
            if exploit.test_binary():
                l.info('Binary POV passed simulation tests!')
            else:
                l.error('ColorGuard created POV for Testcase %d, but if failed!', job.input_test.id)

            Exploit.create(cbn=self._cbn, job=self._job, pov_type='type2',
                           exploitation_method=exploit.method_name,
                           blob=exploit.dump_binary())
