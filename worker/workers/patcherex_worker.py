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
        output_data = pm.run()

        ChallengeBinaryNode.create(parent=job.cbn, cs_id=job.cbn.cs_id, name=job.cbn.name+"_patched", blob=output_data)



