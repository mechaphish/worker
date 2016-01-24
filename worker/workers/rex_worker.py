from ..worker import Worker
import crscommon
import rex
import os

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

        self._job = job

        # TODO: event should be more flexible
        binary_path = os.path.join('cbs/qualifier_event', job.ct_id, job.binary_id)
        # TODO: handle the possibility of a job submitting a PoV, rex already supports this
        crash = rex.Crash(binary_path, job.crashing_testcase.text)

        # maybe we need to do some exploring first
        while not crash.exploitable():
            if not crash.explorable():
                raise ValueError("crash was explored, but ultimately could not be exploited")
            l.info("exploring crash in hopes of getting something more valuable")
            crash.explore() # produce a new testcase here as well? crash.explore('new-testcase')

        # see if we can immiediately begin exploring the crash
        exploits = crash.exploit()

        if exploits.best_type1 is None and exploits.best_type2 is None:
            raise rex.CannotExploit("crash had symptoms of exploitable, but no exploits could be built")

        l.info("crash was able to be exploited")
        l.debug("can set %d registers with type-1 exploits", len(exploits.register_setters))
        l.debug("generated %d type-2 exploits", len(exploits.leakers))
        # return (type1 exploit, type2 exploit), none if they don't exist
        return(exploits.best_type1, exploits.best_type2)

    def run(self, job):
        try:
            exp = self._run(job)
        except (rex.CannotExploit, ValueError) as e:
            l.error(e)

            testcase = job.crashing_testcase
            testcase.explorable = False
            testcase.exploitable = False

            l.info("updating testcase as neither exploitable or explorable")
            crscommon.api.update_testcase(testcase)

            exp = None, None

        return exp
