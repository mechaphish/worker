from ..worker import Worker
import crscommon
import driller

import logging
l = logging.getLogger('crs.worker.workers.driller_worker')
l.setLevel('DEBUG')

class DrillerWorker(Worker):
    def __init__(self):
        self._seen = set()
        self._driller = None

    def run(self, job):
        '''
        Runs AFL with the specified number of cores.
        '''

        self._driller = driller.Driller(job.binary.path, job.testcase.text, job.binary.bitmap, 'tag')
        testcases = self._driller.drill()
        for t in testcases:
            l.info("Got a testcase!")
            job.binary.add_testcase(crscommon.api.Testcase(job.binary, text=t)) # TODO: what if this crashes?
