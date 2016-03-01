from setuptools import setup

setup(
    name='worker',
    version='0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1',
    packages=[ 'worker', 'worker.workers' ],
    scripts=['bin/worker'],
    install_requires=[i.strip() for i in open('requirements.txt').readlines() if 'git' not in i],
    description='Worker component of the Shellphish CRS.',
    url='https://git.seclab.cs.ucsb.edu/cgc/worker',
)
