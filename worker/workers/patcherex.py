#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

from farnsworth.models import ChallengeBinaryNode
from patcherex.patch_master import PatchMaster

import worker.workers
LOG = worker.workers.LOG.getChild('patcherex')
LOG.setLevel('DEBUG')


class PatcherexWorker(worker.workers.Worker):
    def __init__(self):
        super(PatcherexWorker, self).__init__()

    def _run(self, job):
        input_file = job.cbn.path
        pm = PatchMaster(input_file)
        patches = pm.run(return_dict=True)

        for patch_type, p in patches.iteritems():
            name = "{}_patched_{}".format(job.cbn.name, patch_type)
            ChallengeBinaryNode.create(
                root=job.cbn,
                cs=job.cbn.cs,
                name=name,
                patch_type=patch_type,
                blob=p)
