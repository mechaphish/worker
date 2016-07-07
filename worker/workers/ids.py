#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""Generate simple IDS rules from Jacopo's examples."""

from __future__ import unicode_literals, absolute_import

import os
import glob

from farnsworth.models import IDSRule

import worker.workers
LOG = worker.workers.LOG.getChild('ids')
LOG.setLevel('DEBUG')


class IDSWorker(worker.workers.Worker):
    """Generate simple IDS rules from Jacopo's examples."""
    def __init__(self):
        rules_dir = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "../../../ids_rules",
            "*.rules"
        )
        self._rules = sorted(glob.glob(rules_dir))

    def run(self, job):
        for rule_path in self._rules:
            rules = open(rule_path, 'r').read()
            IDSRule.create(cs=job.cs, rules=rules)
