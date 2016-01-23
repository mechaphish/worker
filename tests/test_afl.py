import worker, crscommon
import timeout_decorator

def test_ccf3d301():
    aw = worker.AFLWorker()
    aj = crscommon.jobs.AFLJob('ccf3d301', 'ccf3d301_01')

    @timeout_decorator.timeout(30)
    def _timeout_run():
        aw.run(aj)

    try:
        _timeout_run()
    except timeout_decorator.TimeoutError:
        pass

    print "Found %d crashes" % len(aw._fuzzer.crashes())
    assert len(aw._fuzzer.crashes()) > 0

if __name__ == '__main__':
    test_ccf3d301()
