"""Shellphish CRS worker setuptools."""

from setuptools import setup

# Read requirements from requirements.txt
requires = []   # pylint: disable=invalid-name
with open("requirements.txt") as requirements:
    for requirement in requirements:
        if "git" not in requirement:
            requires.append(requirement.strip())

setup(name='worker',
      version="0.0.2",
      packages=["worker", "worker.workers"],
      scripts=["bin/worker"],
      install_requires=requires,
      description="Worker component of the Shellphish CRS.",
      url="https://github.com/mechaphish/worker")
