from ..worker import Worker
from farnsworth.models import Test, Exploit
import rex
import tracer

import logging
l = logging.getLogger('crs.worker.workers.rex_worker')
l.setLevel('DEBUG')

class RexWorker(Worker):
    def __init__(self):
        self._job = None
        self._cbn = None
        self._exploits = None
        self._crash = None

    def _run(self, job):
        '''
        Runs rex on the crashing testcase.
        '''

        self._job = job
        self._cbn = job.cbn

        # TODO: handle the possibility of a job submitting a PoV, rex already supports this
        crashing_test = job.input_crash
        if crashing_test.triaged:
            l.error("Rex was passed an already triaged testcase, refusing to exploit it")
            return

        l.info("Rex beginning to triage crash %d for cbn %d", crashing_test.id, self._cbn.id)

        # let everyone know this crash has been traced
        crashing_test.triaged = True
        crashing_test.save()

        crash = rex.Crash(self._cbn.path, str(crashing_test.blob))
        self._crash = crash

        if not crash.exploitable() and not crash.explorable():
            raise ValueError("Crash was not exploitable or explorable")

        # maybe we need to do some exploring first
        while crash.explorable():
            l.info("exploring crash in hopes of getting something more valuable")

            # simultaneously explore and dump the new input into a file
            crash.explore('/tmp/new-testcase')

            # upload the new testcase
            # FIXME: we probably want to store it in a different table with custom attrs
            Test.create(cbn=self._cbn, job=self._job, blob=open('/tmp/new-testcase').read())

        # see if we can immiediately begin exploring the crash
        exploits = crash.exploit()
        self._exploits = exploits

        if exploits.best_type1 is None and exploits.best_type2 is None:
            raise rex.CannotExploit("crash had symptoms of exploitability, but no exploits could be built")

        l.info("crash was able to be exploited")
        l.debug("can set %d registers with type-1 exploits", len(exploits.register_setters))
        l.debug("generated %d type-2 exploits", len(exploits.leakers))
        # return (type1 exploit, type2 exploit), none if they don't exist

        for reg in exploits.register_setters:
            exploit = exploits.register_setters[reg]

            l.info("Adding %s type 1!", exploit.method_name)
            Exploit.create(cbn=self._cbn, job=self._job, pov_type='type1',
                           exploitation_method=exploit.method_name,
                           blob=exploits.best_type1.dump_binary())
            self._cbn.save()

        for exploit in exploits.leakers:
            l.info("Adding %s type 2!", exploit.method_name)
            Exploit.create(cbn=self._cbn, job=self._job, pov_type='type2',
                           exploitation_method=exploit.method_name,
                           blob=exploits.best_type2.dump_binary())

    def run(self, job):
        try:
            self._run(job)
        except (rex.CannotExploit, ValueError, tracer.tracer.TracerMisfollowError) as e:
            job.input_crash.explorable = False
            job.input_crash.exploitable = False
            job.input_crash.save()
            # FIXME: log exception somewhere
            l.error(e)
