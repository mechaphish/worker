from ..worker import Worker
import pwnrex

import logging
l = logging.getLogger('crs.worker.workers.pwnrex_worker')
l.setLevel('DEBUG')


class PwnrexWorker(Worker):
    def __init__(self):
        self._job = None

    def _run(self, job):
        '''
        Runs pwnrex.
        '''

        # TODO: handle the possibility of a job submitting a PoV, rex already
        # supports this
        pwnrex.Pwnrex(job.binary.path, job.pcaps)

    def run(self, job):
        self._run(job)
