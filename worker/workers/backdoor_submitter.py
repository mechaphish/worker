#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

from patcherex import patch_master
from farnsworth.models import Exploit

import worker.workers
LOG = worker.workers.LOG.getChild('backdoor_submitter')
LOG.setLevel('INFO')


class BackdoorSubmitterWorker(worker.workers.Worker):

    def __init__(self):
        super(BackdoorSubmitterWorker, self).__init__()

    def _run(self, job):
        """Submit a backdoor POV"""

        LOG.debug("Submitting backdoor for challenge %s", self._cs.name)
        backdoor_blob = str(patch_master.get_backdoorpov())
        Exploit.create(cs=self._cs, job=self._job, pov_type='type1',
                       method='backdoor', blob=backdoor_blob, reliability=0)
