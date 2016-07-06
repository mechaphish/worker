"""Generate simple IDS rules from Jacopo's examples."""

import angr
import identifier
from ..worker import Worker
from farnsworth.models import FunctionIdentity

import logging
l = logging.getLogger('crs.worker.workers.function_identifier_worker')
l.setLevel('DEBUG')

class FunctionIdentifierWorker(Worker):
    """Generate simple identities for functions, will be used to hook up simprocedues."""
    def __init__(self):
        self._job = None
        self._cbn = None

    def run(self, job):

        self._job = job
        self._cbn = job.cbn
        # TODO enfore time limit

        project = angr.Project(self._cbn.path)
        l.info("Inititalizing Identifier")
        idfer = identifier.Identifier(project)

        l.info("Identifier initialized running...")

        idfer.run()

        l.info("Identified %d functions", len(idfer.matches))

        for function in idfer.matches:
            address = function.addr
            symbol = idfer.matches[function][0]
            l.debug("Function %s found at address %#x", symbol, address)
            FunctionIdentity.create(cbn=self._cbn, address=address, symbol=symbol)

        l.info("Done identifying functions for challenge %s", self._cbn.name)
