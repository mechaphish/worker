#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

import pwnrex

import worker.workers
LOG = worker.workers.LOG.getChild('pwnrex')
LOG.setLevel('DEBUG')


class PwnrexWorker(worker.workers.Worker):
    def __init__(self):
        super(PwnrexWorker, self).__init__()

    def _run(self, job):
        '''
        Runs pwnrex.
        '''

        # TODO: handle the possibility of a job submitting a PoV, rex already
        # supports this
        pwnrex.Pwnrex(job.binary.path, job.pcaps)
