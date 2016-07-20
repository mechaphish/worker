#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

import worker.workers
LOG = worker.workers.LOG.getChild('povfuzzer2')
LOG.setLevel('DEBUG')


class PovFuzzer2Worker(worker.workers.VMWorker):
    def __init__(self):
        super(PovFuzzer2Worker, self).__init__()
        self._exploits = None
        self._crash = None

    def _start(self, job):
        """Runs PovFuzzer on the crashing testcase."""
        assert not self._cs.is_multi_cbn, "PovFuzzer2 can only be run on single CBs for now"

        LOG.info("Pov fuzzer 2 about to try for job %d", job.id)
        LOG.info("Pov fuzzer 2 running ssh command")
        LOG.info("we should have %d cores", job.limit_cpu)
        self.execute("python /root/pov_fuzzing/main_type2.py %d" % job.id)

        crashing_test = job.input_crash

        LOG.info("Pov fuzzer 2 beginning to exploit crash %d for challenge %s", crashing_test.id, self._cs.name)
        pov_fuzzer = rex.pov_fuzzing.Type2CrashFuzzer(self._cbn.path, crash=str(crashing_test.blob))

        if pov_fuzzer.exploitable():
            Exploit.create(cs=self._cs, job=self._job, pov_type='type1',
                           method="type1fuzzer",
                           c_code=pov_fuzzer.dump_c(),
                           blob=pov_fuzzer.dump_binary())
            LOG.info("Crash was able to be exploited")
        else:
            LOG.warning("Not exploitable")

        if pov_fuzzer.dumpable():
            # FIXME: we probably want to store it in a different table with custom attrs
            Test.get_or_create(cs=self._cs, job=self._job, blob=pov_fuzzer.get_leaking_payload())
            LOG.info("Possible leaking test was created")
        else:
            LOG.warning("Couldn't even dump a leaking input")

    def _run(self, job):
        try:
            self._start(job)
        except (rex.CannotExploit, ValueError) as e:
            LOG.error(e)
