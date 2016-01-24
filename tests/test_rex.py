import worker, crscommon

def test_ccf3d301_exploitation():
    rw = worker.RexWorker()

    rexploit = crscommon.Testcase(text="1\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n1\n1\n1\n")

    rj = crscommon.jobs.RexJob('ccf3d301', 'ccf3d301_01', rexploit)

    type1, type2 = rw.run(rj)

    # for this binary we can create type-1 exploits, but not type-2s
    assert not type1 is None
    assert type2 is None

if __name__ == '__main__':
    test_ccf3d301_exploitation()
