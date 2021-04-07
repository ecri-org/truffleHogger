import os
from setuptools import setup

version_file = open(os.path.join(os.getcwd(), 'version'))
version = version_file.read().strip()

setup(
    name='trufflehogger',
    version=version,
    description='Searches through git repositories for high entropy strings, digging deep into commit history.',
    url='https://git-mirror.ecri.org/OPS/apps/trufflehogger',
    author='Modified by Jason Giedymin for ECRI, source originally from Dylan Ayrey',
    author_email='jgiedymin@ecri.org',
    license='GNU',
    packages=['truffleHogger'],
    package_data={'': ['regexes.json']},
    install_requires=[
        'GitPython == 3.0.6'
    ],
    entry_points={
      'console_scripts': ['trufflehogger = truffleHogger.truffleHogger:main'],
    },
    python_requires='>=3.7'
)
