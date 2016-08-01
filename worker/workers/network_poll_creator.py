#!/usr/bin/env python2
# -*- coding: utf-8 -*-

"""Create raw CFE POLL from captured network traffic"""

from __future__ import absolute_import, unicode_literals

import os

from network_poll_creator import TrafficProcessor
from farnsworth.models import NetworkPollCreatorJob
from farnsworth.models.raw_round_poll import RawRoundPoll
from farnsworth.models.challenge_set import ChallengeSet

import worker.workers
LOG = worker.workers.LOG.getChild('network_poll_creator')
LOG.setLevel('DEBUG')


class NetworkPollCreatorWorker(worker.workers.Worker):
    """Create CFE POLL from captured network traffic."""

    def __init__(self):
        super(self.__class__, self).__init__()

    def _run(self, job):
        assert isinstance(job, NetworkPollCreatorJob)

        # Save the pickled data into a file
        curr_pcap_file_path = os.path.join(os.path.expanduser('~'),
                                           str(job.id) + '_pickled_pcap')
        round_traffic = job.target_round_traffic
        LOG.info("Trying to create poll for round %s", round_traffic.round.num)
        with open(curr_pcap_file_path, 'wb') as fp:
            fp.write(round_traffic.pickled_data)

        # Process the pickled file
        traffic_processor = TrafficProcessor(curr_pcap_file_path)

        # Process the polls
        count = 0
        for cs, xml, curr_poll in ((p.cs_id, p.to_cfe_xml(), p) for p in traffic_processor.get_polls()):
            cs = ChallengeSet.get(ChallengeSet.name == cs)
            if cs is not None and xml is not None:
                RawRoundPoll.create(round=round_traffic.round, cs=cs,
                                    blob=xml, raw_round_traffic=round_traffic)
                count += 1
            elif cs is None:
                LOG.error("Unable to find ChallengeSet for id %s, ignoring poll",
                          curr_poll.cs_id)
            elif xml is None:
                LOG.warning("Ignoring poll for ChallengeSet %s, we failed to sanitize it",
                            curr_poll.cs_id)

        round_traffic.processed = True
        round_traffic.save()
        LOG.info("Created %s in round %s", count, round_traffic.round.num)
        os.unlink(curr_pcap_file_path)
