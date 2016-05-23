from ..worker import Worker
from farnsworth.models import ChallengeBinaryNode

from patcherex.patch_master import PatchMaster

import logging
l = logging.getLogger('crs.worker.workers.pathcerex_worker')
l.setLevel('DEBUG')

class PatcherexWorker(Worker):
    def __init__(self):
        self._job = None

    def run(self, job):
        input_file = job.cbn.path
        pm = PatchMaster(input_file)
        patches = pm.run()

        for i,p in enumerate(patches):
            ChallengeBinaryNode.create(
                parent=job.cbn,
                root=job.cbn,
                cs=job.cbn.cs,
                name=job.cbn.name+"_patched_"+str(i),
                blob=p)
