"""Create raw CFE POLL from captured network traffic"""

import os
from network_poll_creator import TrafficProcessor
from farnsworth.models.raw_round_poll import RawRoundPoll
from farnsworth.models.challenge_set import ChallengeSet
from ..worker import Worker

import logging
l = logging.getLogger('crs.worker.workers.network_poll_worker')
l.setLevel('DEBUG')


class NetworkPollWorker(Worker):
    """Create CFE POLL from captured network traffic"""

    def run(self, job):
        # Save the pickled data into a file
        curr_pcap_file_path = os.path.join(os.path.expanduser('~'), str(job.id) + '_pickled_pcap')
        round_traffic = job.target_round_traffic
        l.info("Trying to create poll for Round:" + str(round_traffic.round.num))
        fp = open(curr_pcap_file_path, 'wb')
        fp.write(job.pickled_data)
        fp.close()
        # Process the pickled file
        traffic_processor = TrafficProcessor(curr_pcap_file_path)
        # Process the polls
        all_polls = traffic_processor.get_polls()
        for curr_poll in all_polls:
            target_cs = ChallengeSet.find(curr_poll.cs_id)
            if target_cs is not None:
                RawRoundPoll.create(round=round_traffic.round, cs=target_cs, blob=curr_poll.to_cfe_xml())
            else:
                l.error("Unable to find ChallengeSet for Id:" + str(curr_poll.cs_id) + " Ignoring the poll.")
        l.info("Created:" + str(len(all_polls)) + " in Round:" + str(round_traffic.round.num))
        os.system('rm ' + curr_pcap_file_path)
