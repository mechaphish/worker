#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import contextlib
import pickle
import socket

import paramiko
import subprocess32 as subprocess
import tracer
from farnsworth.models import TracerCache, ChallengeBinaryNode

import worker.log
LOG = worker.log.LOG.getChild('workers')


class CRSTracerCacheManager(tracer.cachemanager.CacheManager):
    """CRSTracerCacheManager

    This class manages tracer caches for a given worker. Under-the-hood tracer
    will call into this code to both load and store caches.
    """
    def __init__(self):
        super(self.__class__, self).__init__()
        self.log = worker.log.LOG.getChild('cachemanager')
        self.cbn = None

    def cache_lookup(self):
        # Might better be a property?
        if self.cbn is not None:
            rdata = None
            try:
                cached = TracerCache.get(TracerCache.cbn == self.cbn)
                self.log.info("Loaded tracer state from cache for %s", self.cbn.name)
                return pickle.loads(str(cached.blob))
            except TracerCache.DoesNotExist:
                self.log.debug("No cached states found for %s", self.cbn.name)
        else:
            self.log.warning("cachemanager's cbn was never set, no cache to retrieve")

    def cacher(self, simstate):
        if self.cbn is not None:
            cache_data = self._prepare_cache_data(simstate)
            if cache_data is not None:
                self.log.info("Caching tracer state for challenge %s", self.cbn.name)
                TracerCache.create(cbn=self.cbn, blob=cache_data)
        else:
            self.log.warning("ChallengeBinaryNode was never set by 'set_cbn' cannot cache")


class Worker(object):
    def __init__(self):
        # Tracer cache set up for every job in case they use tracer
        self.tracer_cache = CRSTracerCacheManager()
        tracer.tracer.GlobalCacheManager = self.tracer_cache

        self._job = None
        self._cbn = None

    def _run(self, job):
        raise NotImplementedError("Worker must implement _run(self, job)")

    def run(self, job):
        # Set up job, cbn, and tracer cache
        self._job = job
        self._cbn = job.cbn
        self.tracer_cache.cbn = self._cbn

        self._run(job)


class VMWorker(Worker):
    def __init__(self, disk="/data/cgc-vm.qcow2", kvm_timeout=5, restrict_net=False, sandbox=True,
                 snapshot=True, ssh_port=8022, ssh_username="root", ssh_keyfile="/data/cgc-vm.key",
                 ssh_timeout=30, vm_name=None):
        super(Worker, self).__init__()
        self._disk = disk
        self._kvm_timeout = kvm_timeout
        self._restrict_net = 'on' if restrict_net else 'off'
        self._sandbox = 'on' if sandbox else 'off'
        self._snapshot = 'on' if snapshot else 'off'
        self._ssh_keyfile = ssh_keyfile
        self._ssh_port = ssh_port
        self._ssh_timeout = ssh_timeout
        self._ssh_username = ssh_username
        self._vm_name = vm_name if vm_name is not None else "cgc"

    @contextlib.contextmanager
    def vm(self):
        LOG.debug("Spawning up VM to run jobs within")
        drive = "file={0._disk},media=disk,discard=unmap,snapshot={0._snapshot},if=virtio".format(self)
        netdev = ("user,id=fakenet0,net=172.16.6.0/24,restrict={0._restrict_net},"
                  "hostfwd=tcp:127.0.0.1:{0._ssh_port}-:22,").format(self)

        kvm_command = ["kvm", "-name", self._vm_name,
                       "-sandbox", self._sandbox,
                       "-machine", "pc-i440fx-1.7,accel=kvm,usb=off",
                       "-cpu", "SandyBridge",
                       "-snapshot",
                       "-drive", drive,
                       "-netdev", netdev,
                       "-net", "nic,netdev=fakenet0,model=virtio",
                       "-daemonize"]
        try:
            kvm_process = subprocess.Popen(kvm_command, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        except OSError as e:
            LOG.error("Is KVM installed? Popen raised %s", e)
            raise EnvironmentError("Unable to start VM, KVM process failed %s", e)

        try:
            stdout, stderr = kvm_process.communicate(timeout=self._kvm_timeout)
        except TimeoutExpired:
            LOG.error("VM did not start within %s seconds, killing it", self._kvm_timeout)
            LOG.debug("stdout: %s", stdout)
            LOG.debug("stderr: %s", stderr)
            kvm_process.kill()

            LOG.warning("5 seconds grace period before forcefully killing VM")
            time.sleep(5)
            kvm_process.terminate()
            raise EnvironmentError("KVM start did not boot up properly")

        LOG.debug("Connecting to the VM via SSH")
        self.ssh = paramiko.client.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        try:
            self.ssh.connect("127.0.0.1", port=self._ssh_port, username=self._ssh_username,
                            key_filename=self._ssh_keyfile, timeout=self._ssh_timeout)
            # also raises BadHostKeyException, should be taken care of via AutoAddPolicy()
            # also raises AuthenticationException, should never occur because keys are provisioned
        except socket.error as e:
            raise EnvironmentError("Unable to connect to VM. VM might have not booted yet. "
                                   "TCP error: %s", e)
        except paramiko.SSHException as e:
            raise EnvironmentError("Unable to connect to VM. VM might have not booted yet. "
                                   "SSH error: %s", e)

        LOG.debug("Setting up route to database etc.")
        try:
            self.ssh.exec_command("ip r add default via 172.16.6.2")
        except paramiko.SSHException as e:
            raise EnvironmentError("Unable to setup routes on host: %s", e)

        LOG.debug("Passing control over to the Worker")
        yield

        LOG.debug("Worker finished, cleaning up SSH connection and VM")
        self.ssh.close()
        kvm_process.terminate()

    def run(self, job):
        try:
            with self.vm():
                # Run Worker.run()
                super(Worker, self).run(self, job)
        except EnvironmentError as e:
            LOG.error("Error preparing VM for execution: %s", e)
