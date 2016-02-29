from ..worker import Worker
from farnsworth_client.models import Test
import driller

import logging
l = logging.getLogger('crs.worker.workers.driller_worker')
l.setLevel('DEBUG')

class DrillerWorker(Worker):
    def __init__(self):
        self._seen = set()
        self._driller = None
        self._job = None
        self._cbn = None

    def run(self, job):
        '''
        Drills a testcase.
        '''

        self._job = job
        self._cbn = job.cbn

        self._driller = driller.Driller(self._cbn.binary_path, job.payload.blob, self._cbn.bitmap.blob, 'tag')
        for _,t in self._driller.drill_generator():
            l.info("Found new testcase!")
            job._cbn.add_test(Test(job_id=self._job.id, blob=t))
            job._cbn.save()
