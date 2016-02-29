from ..worker import Worker
from farnsworth_client.models import Test, Exploit
import rex

import logging
l = logging.getLogger('crs.worker.workers.rex_worker')
l.setLevel('DEBUG')

class RexWorker(Worker):
    def __init__(self):
        self._job = None
        self._cbn = None

    def _run(self, job):
        '''
        Runs rex on the crashing testcase.
        '''

        self._job = job
        self._cbn = job.cbn

        # TODO: handle the possibility of a job submitting a PoV, rex already supports this
        crashing_test = job.payload
        crash = rex.Crash(job.cbn.binary_path, crashing_test.blob)

        # maybe we need to do some exploring first
        while not crash.exploitable():
            if not crash.explorable():
                raise ValueError("crash was explored, but ultimately could not be exploited")
            l.info("exploring crash in hopes of getting something more valuable")

            # simultaneously explore and dump the new input into a file
            crash = crash.explore('/tmp/new-testcase')

            # upload the new testcase
            # FIXME: we probably want to store it in a different table with custom attrs
            self._cbn.tests += [Test(job_id=self._job.id, type='test', blob=open('/tmp/new-testcase').read())]
            self._cbn.save()

        # see if we can immiediately begin exploring the crash
        exploits = crash.exploit()

        if exploits.best_type1 is None and exploits.best_type2 is None:
            raise rex.CannotExploit("crash had symptoms of exploitability, but no exploits could be built")

        l.info("crash was able to be exploited")
        l.debug("can set %d registers with type-1 exploits", len(exploits.register_setters))
        l.debug("generated %d type-2 exploits", len(exploits.leakers))
        # return (type1 exploit, type2 exploit), none if they don't exist

        if exploits.best_type1 is not None:
            l.info("Adding type 1!")
            self._cbn.exploits += [Exploit(cbn_id=self._cbn.id, pov_type=1, payload=exploits.best_type1.pov())]
            self._cbn.save()
        if exploits.best_type2 is not None:
            l.info("Adding type 2!")
            self._cbn.exploits += [Exploit(cbn_id=self._cbn.id, pov_type=2, payload=exploits.best_type2.pov())]
            self._cbn.save()

    def run(self, job):
        try:
            self._run(job)
        except (rex.CannotExploit, ValueError) as e:
            l.error(e)
            # FIXME
            # testcase = job.crashing_testcase
            # testcase.explorable = False
            # testcase.exploitable = False
