import os
import worker, crscommon
from farnsworth_client.models import Job, ChallengeBinaryNode
import timeout_decorator

def test_ccf3d301():
    aw = worker.AFLWorker()
    ### FIXME: nedd to use a mock or factory library
    aj = Job(id='xxx', worker='afl', cbn_id='xxx', limit_cpu=4, limit_memory=1, payload=None)
    aj._cbn = ChallengeBinaryNode(id='xxx', name='ccf3d301_01', blob=None)
    aj._cbn._binary_path = os.path.join('../cbs/qualifier_event/ccf3d301', 'ccf3d301_01')
    aj._cbn._tests = []
    ###

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
