#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""Load settings from environment variables."""

from __future__ import unicode_literals, absolute_import

from os.path import join, dirname

from dotenv import load_dotenv

load_dotenv(join(dirname(__file__), '../.env'))
