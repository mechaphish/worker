from ..worker import Worker
import crscommon
import rex

import logging
l = logging.getLogger('crs.worker.workers.rex_worker')
l.setLevel('DEBUG')

class RexWorker(Worker):
    def __init__(self):
        self._job = None

    def _run(self, job):
        '''
        Runs rex on the crashing testcase.
        '''

        # TODO: handle the possibility of a job submitting a PoV, rex already supports this
        crash = rex.Crash(job.binary.path, job.crashing_testcase.text)

        # maybe we need to do some exploring first
        while not crash.exploitable():
            if not crash.explorable():
                raise ValueError("crash was explored, but ultimately could not be exploited")
            l.info("exploring crash in hopes of getting something more valuable")

            # simultaneously explore and dump the new input into a file
            crash = crash.explore('/tmp/new-testcase')

            # upload the new testcase
            tcase = crscommon.api.Testcase(self._job.binary, text=open('/tmp/new-testcase').read())
            job.binary.add_testcase(tcase)

        # see if we can immiediately begin exploring the crash
        exploits = crash.exploit()

        if exploits.best_type1 is None and exploits.best_type2 is None:
            raise rex.CannotExploit("crash had symptoms of exploitable, but no exploits could be built")

        l.info("crash was able to be exploited")
        l.debug("can set %d registers with type-1 exploits", len(exploits.register_setters))
        l.debug("generated %d type-2 exploits", len(exploits.leakers))
        # return (type1 exploit, type2 exploit), none if they don't exist

        if exploits.best_type1 is not None:
            l.info("Adding type 1!")
            job.binary.add_exploit(exploits.best_type1)
        if exploits.best_type2 is not None:
            l.info("Adding type 2!")
            job.binary.add_exploit(exploits.best_type2)

    def run(self, job):
        try:
            self._run(job)
        except (rex.CannotExploit, ValueError) as e:
            l.error(e)

            testcase = job.crashing_testcase
            testcase.explorable = False
            testcase.exploitable = False
