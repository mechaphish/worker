#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import worker.log

LOG = worker.log.LOG.getChild('workers')

class Worker(object):
    def run(self, job):
        raise NotImplementedError()