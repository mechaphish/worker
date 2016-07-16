#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

import hashlib

from farnsworth.models import ChallengeBinaryNode, IDSRule
from patcherex.patch_master import PatchMaster

import worker.workers
LOG = worker.workers.LOG.getChild('patcherex')
LOG.setLevel('DEBUG')


class PatcherexWorker(worker.workers.Worker):
    def __init__(self):
        super(PatcherexWorker, self).__init__()

    def _run(self, job):
        input_file = job.cbn.path
        patch_type = job.payload["patch_type"]
        pm = PatchMaster(input_file)
        patched_bin, ids_rule = pm.create_one_patch(patch_type)

        name = "{}_patched_{}".format(job.cbn.name, patch_type)
        ids = IDSRule.get_by_sha256_or_create(rules=ids_rule, cs=job.cbn.cs)
        ChallengeBinaryNode.create(
            root=job.cbn,
            cs=job.cbn.cs,
            name=name,
            patch_type=patch_type,
            blob=patched_bin,
            sha256=hashlib.sha256(patched_bin).hexdigest(),
            ids_rule=ids,
        )
