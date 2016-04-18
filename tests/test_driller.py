import worker

def test_ccf3d301_empty_bitmap():
    b = crscommon.api.Binary('ccf3d301_01', crscommon.api.ChallengeTree('ccf3d301'))
    b.bitmap = "\xff" * 2**16
    t = crscommon.api.Testcase(b, text="1\nBBBBBBBBBBBBBBB\n\n\n\n")
    dj = crscommon.jobs.DrillerJob(b, t)
    dw = worker.DrillerWorker()
    dw.run(dj)

    print "Found %d new testcases with empty bitmap" % len(b.testcases)
    assert len(b.testcases) > 0

def test_ccf3d301_full_bitmap():
    b = crscommon.api.Binary('ccf3d301_01', crscommon.api.ChallengeTree('ccf3d301'))
    b.bitmap = "\x00" * 2**16
    t = crscommon.api.Testcase(b, text="1\nBBBBBBBBBBBBBBB\n\n\n\n")
    dj = crscommon.jobs.DrillerJob(b, t)
    dw = worker.DrillerWorker()
    dw.run(dj)

    print "Found %d new testcases with full bitmap" % len(b.testcases)
    assert len(b.testcases) == 0

if __name__ == '__main__':
    test_ccf3d301_full_bitmap()
    test_ccf3d301_empty_bitmap()
