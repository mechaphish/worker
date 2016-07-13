#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, absolute_import

import threading
import time

import worker.workers

LOG = worker.workers.LOG.getChild('test')
LOG.setLevel('DEBUG')


class TestWorker(worker.workers.Worker):
    def __init__(self, number_of_vms=2):
        super(self.__class__, self).__init__()
        self.free_vms = set()

    @staticmethod
    def parse_cb_test_out(output_buf):
        final_result = None
        performance_json = {"rss": 0.0, "flt": 0.0, "filesize": 0.0,  "cpu_clock": 0.0, "task_clock": 0.0}

        # Performance counters
        # Format: (key check, split value, json key)
        performance_counters = {("cb-server: total maxrss", "total maxrss", "rss"),
                                ("cb-server: total minflt", "total minflt", "flt"),
                                ("cb-server: total sw-cpu-clock", "sw-cpu-clock", "cpu_clock"),
                                ("cb-server: total sw-task-clock", "sw-task-clock", "task_clock"),
                                ("cb-server: stat:", "filesize", "filesize")}
        total_failed = -1
        for curr_line in output_buf.split("\n"):
            for curr_perf_tuple in performance_counters:
                if (curr_perf_tuple[0] in curr_line) and len(curr_line.split(curr_perf_tuple[1])) > 1:
                    performance_json[curr_perf_tuple[2]] = float(curr_line.split(curr_perf_tuple[1])[1].strip())
            if "total tests failed" in curr_line:
                total_failed = int(curr_line.split(":")[1])
            elif "SIGSEGV" in curr_line or "SIGFPE" in curr_line or "SIGILL" in curr_line:
                final_result = "C"
            elif "SIGALRM" in curr_line or "not ok - process timed out" in curr_line:
                final_result = "F"

        if total_failed > 0:
            final_result = "F"
        elif final_result is not None:
            final_result = "S"

        return final_result, performance_json

    def _run(self, job):
        LOG.debug("Starting Tester worker")

        # Create VM

        # Wait for SSH

        # Spawn worker inside of VM



        try:
            LOG.debug("Starting Test Worker")
            # Get the free VM.
            target_free_vm = self.get_free_vm()
            # Schedule the job
            self._log_run(job, target_free_vm)
            # Restore the free VM
            self.put_free_vm(target_free_vm)
            tries_remaining = MAX_RETRY_TIMES
            idle_sleep_time = (LOITER_TIME*1.0) / MAX_RETRY_TIMES
            while tries_remaining > 0:
                to_run_jobs = self.crshelper.get_testjobs()
                if len(to_run_jobs) > 0:
                    # if there are jobs to run, reset the tries.
                    for curr_job in to_run_jobs:
                        target_free_vm = self.get_free_vm()
                        if self.crshelper.mark_testjob_busy(curr_job):
                            self._log_run(curr_job, target_free_vm)
                        self.put_free_vm(target_free_vm)
                    tries_remaining = MAX_RETRY_TIMES
                else:
                    # Sleep only if there are no jobs to run
                    time.sleep(idle_sleep_time)
                    tries_remaining -= 1
            LOG.debug("Exiting Test Worker as there are no jobs to run")

        except Exception as e:
            LOG.error("Error occurred while trying to run job:" + str(job) + ", Exception:" + str(e))
