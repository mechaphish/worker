from ..worker import Worker
from farnsworth.models import Test
#import driller

import logging
l = logging.getLogger('crs.worker.workers.driller_worker')
l.setLevel('DEBUG')

class DrillerWorker(Worker):
    def __init__(self):
        self._seen = set()
        self._driller = None
        self._job = None
        self._cbn = None
        self._seen = set()

    def run(self, job):
        '''
        Drills a testcase.
        '''

        self._job = job
        self._cbn = job.cbn
        self._job.input_test.drilled = True
        self._job.input_test.save()

        self._driller = driller.Driller(self._cbn.path, job.input_test.blob, self._cbn.bitmap.first().blob, 'tag')
        for _,t in self._driller.drill_generator():
            if t in self._seen:
                continue
            self._seen.add(t)

            l.info("Found new testcase (of length %s)!", len(t))
            Test.create(cbn=self._cbn, job=self._job, blob=t)
