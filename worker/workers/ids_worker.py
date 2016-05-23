"""Generate simple IDS rules from Jacopo's examples."""

import os
import glob
from ..worker import Worker
from farnsworth.models import IDSRule

import logging
l = logging.getLogger('crs.worker.workers.ids_worker')
l.setLevel('DEBUG')

class IDSWorker(Worker):
    """Generate simple IDS rules from Jacopo's examples."""
    def __init__(self):
        rules_dir = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "../../ids_examples",
            "*.rules"
        )
        self._rules = sorted(glob.glob(rules_dir))

    def run(self, job):
        for rule_path in self._rules:
            rules = open(rule_path, 'r').read()
            IDSRule.create(cs=job.cs, rules=rules)
