from ..worker import Worker
from farnsworth.models import Test
from simuvex.procedures import SimProcedures
import driller

import logging
l = logging.getLogger('crs.worker.workers.driller_worker')
l.setLevel('DEBUG')

logging.getLogger("driller").setLevel("INFO")

class DrillerWorker(Worker):

    DONT_HOOK = ["malloc", "free", "realloc", "printf", "snprintf"]

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

        hooks = dict()
        for addr in self._cbn.symbols.keys():
            symbol = self._cbn.symbols[addr]
            if symbol in self.DONT_HOOK:
                continue
            if symbol in SimProcedures['libc.so.6']:
                l.debug('Hooking up %#x -> %s', addr, symbol)
                hooks[addr] = SimProcedures['libc.so.6'][symbol]

        l.debug('Hooked up %d addresses to simprocedures', len(hooks))

        self._driller = driller.Driller(self._cbn.path, job.input_test.blob,
                self._cbn.bitmap.first().blob, 'tag', hooks=hooks)

        for _,t in self._driller.drill_generator():
            if t in self._seen:
                continue
            self._seen.add(t)

            l.info("Found new testcase (of length %s)!", len(t))
            Test.create(cbn=self._cbn, job=self._job, blob=t)

        self._job.input_test.drilled = True
        self._job.input_test.save()
