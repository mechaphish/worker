#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

import fuzzer
from farnsworth.models import Crash, Round, Test
import rex

import worker.workers
LOG = worker.workers.LOG.getChild('showmap_sync')
LOG.setLevel('DEBUG')

class ShowmapSyncWorker(worker.workers.Worker):
    """
    Sync tests and crashes from the network.
    """

    def __init__(self):
        super(ShowmapSyncWorker, self).__init__()
        self._seen = set()
        self._round = None

    def _sync_poll_to_test(self, poll):
        if poll in self._seen: return
        Test.get_or_create(cs=self._cs, job=self._job, blob=poll, drilled=False, poll_created=True)
        self._seen.add(poll)

    def _sync_poll_to_crash(self, poll):
        if poll in self._seen: return

        crash_kind = None
        try:
            qc = rex.QuickCrash(self._cbn.path, poll)
            crash_kind = qc.kind
        except Exception as e:
            LOG.error("QuickCrash triaging threw exception '%s' "
                    "NOT SYNCING", e.message)

        if crash_kind is not None:
            Crash.get_or_create(cs=self._cs, job=self._job, blob=poll,
                    crash_kind=crash_kind, crash_pc=qc.crash_pc, bb_count=qc.bb_count)

        self._seen.add(poll)

    def _run(self, job):
        """Run Showmap on all polls in a round and sync them into Tests if they're new"""

        self._round = self._job.input_round

        if self._cs.is_multi_cbn:
            LOG.warning("Showmap scheduled on multicb, this is not yet supported")
            return

        LOG.debug("Invoking Showmap on polls for challenge %s, round #%d", self._cs.name,
                self._job.input_round.num)

        bitmap = "\xff" # default bitmap all unseen
        if not self._cs.bitmap.exists():
            LOG.warning("No bitmap found for challenge %s, "
                "most likely all polls will be considered interesting", self._cs.name)
        else:
            bitmap = str(self._cs.bitmap.first().blob)

        for poll in self._cs.raw_round_polls.join(Round).where(Round.id == self._round.id):

            as_test = str(poll.from_xml_to_test())
            if len(as_test) == 0:
                continue

            smap = fuzzer.Showmap(self._cbn.path, as_test)
            shownmap = smap.showmap()

            for k in shownmap:
                if shownmap[k] > (ord(bitmap[k%len(bitmap)]) ^ 0xff):
                    LOG.info("Found poll %d interesting, syncing to tests", poll.id)
                    if smap.causes_crash:
                        LOG.info("Poll %d caused a crash!", poll.id)
                        self._sync_poll_to_crash(as_test)
                    else:
                        self._sync_poll_to_test(as_test)
                    break

        LOG.info("Synced %d polls", len(self._seen))
