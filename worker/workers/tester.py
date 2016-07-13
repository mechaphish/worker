#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import threading
import time

import worker.workers
LOG = worker.workers.LOG.getChild('tester')
LOG.setLevel('DEBUG')


class TesterWorker(worker.workers.VMWorker):
    def _run(self, job):
        self.ssh.exec_command("COMMAND GOES HERE")
