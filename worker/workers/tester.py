#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import worker.workers
LOG = worker.workers.LOG.getChild('tester')
LOG.setLevel('DEBUG')


class TesterWorker(worker.workers.VMWorker):
    # maximum number of jobs that need to be run by the VM
    MAX_NUM_JOBS = 1000

    def __init__(self):
        super(self.__class__, self).__init__()

    def _run(self, job):
        job_type = job.payload['type']
        cs_id = job.cs.id
        to_execute_command = "common_tester {} {} {}".format(cs_id, job_type, TesterWorker.MAX_NUM_JOBS)
        self.execute(to_execute_command)

