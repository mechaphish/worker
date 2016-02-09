from distutils.core import setup

setup(
    name='worker',
    version='0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1',
    packages=[ 'worker', 'worker.workers' ],
    scripts=['bin/worker'],
    install_requires=[
        'timeout-decorator',
        'fuzzer',
        'python-dotenv',
        'farnsworth_client',
    ],
    description='Worker component of the Shellphish CRS.',
    url='https://git.seclab.cs.ucsb.edu/cgc/miester',
)
