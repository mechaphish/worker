from ..worker import Worker
import threading
import crscommon
import time

import logging
l = logging.getLogger('crs.worker.workers.perf_test_worker')
l.setLevel('DEBUG')


class PerfTestWorker(Worker):
    def __init__(self, number_of_vms=2):
        self.max_vms = number_of_vms
        self.free_vms = set()
        # Lock to access free VMs.
        self.vm_lock = threading.Lock()
        # TODO: Set up those number of VMs

    def get_free_vm(self):
        """

        :return:
        """
        to_ret = None
        if self.free_vms is not None:
            with self.vm_lock:
                if len(self.free_vms) > 0:
                    to_ret = self.free_vms.pop()
        else:
            l.error("Free VMs member is None. This should never happen.")
        return to_ret

    def put_free_vm(self, to_free_vm):
        """

        :param to_free_vm:
        :return:
        """
        if to_free_vm is not None:
            with self.vm_lock:
                if self.free_vms is None:
                    self.free_vms = set()
                self.free_vms.add(to_free_vm)

    def _run(self, job, test_vm):
        """

        :param job:
        :param test_vm:
        :return:
        """
        # TODO: finish this
        pass

    def run(self, job):
        try:
            # TODO:
            # 1. See if VMs are free
            # 2. Get the free VM.
            target_free_vm = self.get_free_vm()
            # 3. Schedule the job
            self._run(job, target_free_vm)
            pass
        except Exception as e:
            l.error("Error occured while trying to run job:" + str(job) + ", Exception:" + str(e))
