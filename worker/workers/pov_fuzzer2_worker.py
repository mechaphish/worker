from ..worker import Worker
from farnsworth.models import Test, Exploit
import rex.pov_fuzzing

import logging
l = logging.getLogger('crs.worker.workers.pov_fuzzer2_worker')
l.setLevel('DEBUG')


class PovFuzzer2Worker(Worker):
    def __init__(self):
        self._job = None
        self._cbn = None
        self._exploits = None
        self._crash = None

    def _run(self, job):
        """
        Runs PovFuzzer on the crashing testcase.
        """

        self._job = job
        self._cbn = job.cbn

        # TODO: handle the possibility of a job submitting a PoV, rex already supports this
        crashing_test = job.input_crash

        l.info("Pov fuzzer 2 beginning to exploit crash %d for cbn %d", crashing_test.id, self._cbn.id)

        pov_fuzzer = rex.pov_fuzzing.Type2CrashFuzzer(self._cbn.path, crash=str(crashing_test.blob))

        if pov_fuzzer.exploitable():
            Exploit.create(cbn=self._cbn, job=self._job, pov_type='type1',
                           exploitation_method="type1fuzzer",
                           blob=pov_fuzzer.dump_binary())
            l.info("crash was able to be exploited")
        else:
            l.warning("Not exploitable")

        if pov_fuzzer.dumpable():
            # FIXME: we probably want to store it in a different table with custom attrs
            Test.create(cbn=self._cbn, job=self._job, blob=pov_fuzzer.get_leaking_payload())
            l.info("possible leaking test was created")
        else:
            l.warning("Couldn't even dump a leaking input")

    def run(self, job):
        try:
            self._run(job)
        except (rex.CannotExploit, ValueError) as e:
            job.input_crash.exploitable = False
            job.input_crash.save()
            # FIXME: log exception somewhere
            l.error(e)
