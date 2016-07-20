#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import absolute_import, unicode_literals

import contextlib
import os
import pickle
import signal
import socket
import tempfile
import time

import paramiko
import stopit
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
        self.cs = None

    def cache_lookup(self):
        # Might better be a property?
        if self.cs is not None:
            rdata = None
            try:
                cached = TracerCache.get(TracerCache.cs == self.cs)
                self.log.info("Loaded tracer state from cache for %s", self.cs.name)
                return pickle.loads(str(cached.blob))
            except TracerCache.DoesNotExist:
                self.log.debug("No cached states found for %s", self.cs.name)
        else:
            self.log.warning("cachemanager's cs was never set, no cache to retrieve")

    def cacher(self, simstate):
        if self.cs is not None:
            cache_data = self._prepare_cache_data(simstate)
            if cache_data is not None:
                self.log.info("Caching tracer state for challenge %s", self.cs.name)
                TracerCache.create(cs=self.cs, blob=cache_data)
        else:
            self.log.warning("ChallengeSet was never initialized  cannot cache")


class Worker(object):
    def __init__(self):
        LOG.debug("Creating Worker")
        # Tracer cache set up for every job in case they use tracer
        self.tracer_cache = CRSTracerCacheManager()
        tracer.tracer.GlobalCacheManager = self.tracer_cache

        self._job = None
        self._cbn = None
        self._cs = None

    def _run(self, job):
        raise NotImplementedError("Worker must implement _run(self, job)")

    def run(self, job):
        # Set up job, cs, cbn, and tracer cache
        self._job = job
        self._cs = job.cs
        self._cbn = job.cbn
        self.tracer_cache.cs = self._cs

        if self._cs is not None:
            if self._cbn is None and not job.cs.is_multi_cbn:
                self._cbn = self._cs.cbns_original[0]

        self._run(job)


class VMWorker(Worker):
    def __init__(self, disk="/data/cgc-vm.qcow2", kvm_timeout=5, restrict_net=False, sandbox=True,
                 snapshot=True, ssh_port=8022, ssh_username="root", ssh_keyfile="/data/cgc-vm.key",
                 ssh_timeout=30, vm_name=None):
        super(VMWorker, self).__init__()
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
        self._vm_pidfile = None

    def __del__(self):
        """Clean-up method for VMWorker.

        The VMWorker spawns up a VM that might still be running when the
        worker is garbage-collected, which is something that we should
        clean up. If the VM is running, try to kill it, at best effort.
        """
        if self._vm_pidfile is not None:
            if self.vm_pid is not None:
                os.kill(self.vm_pid, signal.SIGKILL)
            self._vm_pidfile.close()

    @property
    def vm_pid(self):  # locally bound to pidfile file handle
        self._vm_pidfile.seek(0)
        pid_ = self._vm_pidfile.read()
        if pid_:
            return int(pid_)

    def _bootup_vm(self):
        """Boot up the VM as, internal helper funtion.

        Note that it opens temporarily file as self._vm_pidfile.
        """
        LOG.debug("Spawning up VM to run jobs within")
        drive = "file={0._disk},media=disk,discard=unmap,snapshot={0._snapshot},if=virtio".format(self)
        netdev = ("user,id=fakenet0,net=172.16.6.0/24,restrict={0._restrict_net},"
                  "hostfwd=tcp:127.0.0.1:{0._ssh_port}-:22,").format(self)
        self._vm_pidfile = tempfile.NamedTemporaryFile(mode='r', prefix="worker-vm", suffix="pid")

        kvm_command = ["kvm", "-name", self._vm_name,
                       "-sandbox", self._sandbox,
                       "-machine", "pc-i440fx-1.7,accel=kvm,usb=off",
                       "-cpu", "SandyBridge",
                       "-snapshot",
                       "-drive", drive,
                       "-netdev", netdev,
                       "-net", "nic,netdev=fakenet0,model=virtio",
                       "-daemonize",
                       "-pidfile", self._vm_pidfile.name,
                       "-vnc", "none"]
        try:
            kvm_process = subprocess.Popen(kvm_command, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        except OSError as e:
            LOG.error("Is KVM installed? Popen raised %s", e)
            raise EnvironmentError("Unable to start VM, KVM process failed %s", e)

        try:
            stdout, stderr = kvm_process.communicate(timeout=self._kvm_timeout)
            LOG.debug("stdout: %s", stdout)
            LOG.debug("stderr: %s", stderr)
        except subprocess.TimeoutExpired:
            LOG.error("VM did not start within %s seconds, killing it", self._kvm_timeout)
            LOG.debug("stdout: %s", stdout)
            LOG.debug("stderr: %s", stderr)
            kvm_process.terminate()
            if self.vm_pid is not None:
                os.kill(self.vm_pid, signal.SIGTERM)

            LOG.warning("5 seconds grace period before forcefully killing VM")
            time.sleep(5)
            kvm_process.kill()
            if self.vm_pid is not None:
                os.kill(self.vm_pid, signal.SIGKILL)

            raise EnvironmentError("KVM start did not boot up properly")

    def _wait_for_ssh(self):
        LOG.debug("Waiting for SSH to become available from worker")
        not_reachable = True
        try:
            # ThreadingTimeout does not work with PyPy, using signals instead
            with stopit.SignalTimeout(self._ssh_timeout, swallow_exc=False):
                while not_reachable:
                    try:
                        connection = socket.create_connection(("127.0.0.1", self._ssh_port))
                        not_reachable = False
                        connection.close()
                    except socket.error as e:
                        LOG.debug("Unable to connect just yet, sleeping")
                        time.sleep(1)
        except stopit.TimeoutException:
            LOG.error("SSH did not become available within %s seconds.", self._ssh_timeout)
            LOG.debug("stdout: %s", stdout)
            LOG.debug("stderr: %s", stderr)
            raise EnvironmentError("SSH did not become available")

    def _initialize_ssh_connection(self):
        LOG.debug("Connecting to the VM via SSH")
        self.ssh = paramiko.client.SSHClient()

        self.ssh.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        try:
            self.ssh.connect("127.0.0.1", port=self._ssh_port, username=self._ssh_username,
                             key_filename=self._ssh_keyfile, timeout=self._ssh_timeout)
            # Set TCP Keep-Alive to 5 seconds, so that the connection does not die
            transport = self.ssh.get_transport()
            transport.set_keepalive(5)
            # also raises BadHostKeyException, should be taken care of via AutoAddPolicy()
            # also raises AuthenticationException, should never occur because keys are provisioned
        except socket.error as e:
            LOG.error("TCP error connecting to SSH on VM.")
            LOG.debug("stdout: %s", stdout)
            LOG.debug("stderr: %s", stderr)
            raise e
        except paramiko.SSHException as e:
            LOG.error("SSH error trying to connect to VM.")
            LOG.debug("stdout: %s", stdout)
            LOG.debug("stderr: %s", stderr)
            raise e

    def execute(self, command):
        assert self.ssh is not None

        environment = " ".join("{}='{}'".format(k, v) for k, v in os.environ.items()
                               if k.startswith("POSTGRES"))
        env_command = "{} {}".format(environment, command)
        LOG.debug("Executing command: %s", env_command)
        try:
            _, stdout, stderr = self.ssh.exec_command(env_command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                raise paramiko.SSHException("'%s' failed with exit status %d", command, exit_status)
        except paramiko.SSHException as e:
            LOG.error("Unable to excute command '%s' on host: %s", command, e)
            LOG.debug("stdout: %s", stdout.read())
            LOG.debug("stderr: %s", stderr.read())
            raise e

    @contextlib.contextmanager
    def vm(self):
        self._bootup_vm()
        self._wait_for_ssh()
        self._initialize_ssh_connection()

        LOG.debug("Setting up route to database etc.")
        self.execute("ip r add default via 172.16.6.2")

        LOG.debug("Passing control over to the Worker")
        yield

        LOG.debug("Worker finished, cleaning up SSH connection and VM")
        self.ssh.close()
        if self.vm_pid is not None:
            # We do not care about the state of the VM anymore, and can -9 it instead of -15
            os.kill(self.vm_pid, signal.SIGKILL)
        self._vm_pidfile.close()

        # If not set to None, deconstructor will try to kill the VM and remove the file
        self._vm_pidfile = None

    def run(self, job):
        try:
            with self.vm():
                super(VMWorker, self).run(job)
        except EnvironmentError as e:
            LOG.error("Error preparing VM for execution: %s", e)
