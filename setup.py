from setuptools import setup

setup(
    name='worker',
    version='0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1',
    packages=[ 'worker', 'worker.workers' ],
    scripts=['bin/worker'],
    install_requires=[
        'python-dotenv==0.3.0',
        'farnsworth_client',
        'fuzzer',
        # test dependencies
        'timeout-decorator',
        'mock>=1.3.0',
        'nose>=1.3.7',
        'nose-timer>=0.5.0',
        'coverage>=4.0.3'
    ],
    description='Worker component of the Shellphish CRS.',
    url='https://git.seclab.cs.ucsb.edu/cgc/miester',
)
