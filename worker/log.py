#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Worker log settings."""

from __future__ import unicode_literals, absolute_import

import logging
import os
import sys

DEFAULT_FORMAT = '%(asctime)s - %(name)-30s - %(levelname)-10s - %(message)s'

LOG = logging.getLogger('worker')
LOG.setLevel(os.environ.get('WORKER_LOG_LEVEL', 'DEBUG'))

HANDLER = logging.StreamHandler(sys.stdout)
HANDLER.setFormatter(logging.Formatter(os.environ.get('WORKER_LOG_FORMAT', DEFAULT_FORMAT)))
LOG.addHandler(HANDLER)