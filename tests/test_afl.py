import worker, crscommon
import timeout_decorator

def test_ccf3d301():
    aw = worker.AFLWorker()
    aj = crscommon.jobs.AFLJob(crscommon.api.Binary('ccf3d301_01', crscommon.api.ChallengeTree('ccf3d301')))

    @timeout_decorator.timeout(30)
    def _timeout_run():
        aw.run(aj)

    try:
        _timeout_run()
    except timeout_decorator.TimeoutError:
        pass

    print "Found %d crashes" % len(aw._fuzzer.crashes())
    assert len(aj.binary.crashes) > 0

if __name__ == '__main__':
    test_ccf3d301()
