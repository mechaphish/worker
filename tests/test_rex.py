# import worker, crscommon

# def test_ccf3d301_exploitation():
#     rw = worker.RexWorker()

#     binary = crscommon.api.Binary('ccf3d301_01', crscommon.api.ChallengeTree('ccf3d301'))
#     rexploit = crscommon.api.Testcase(binary, text="1\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n1\n1\n1\n")

#     rj = crscommon.jobs.RexJob(binary, rexploit)

#     rw.run(rj)

#     # for this binary we can create type-1 exploits, but not type-2s
#     assert len(binary.exploits) == 1
#     assert binary.exploits[0].cgc_type == 1

# if __name__ == '__main__':
#     test_ccf3d301_exploitation()
