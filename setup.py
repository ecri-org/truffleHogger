from setuptools import setup, find_packages

setup(
    name='truffleHogger',
    version='3.0.0',
    description='Searches through git repositories for high entropy strings, digging deep into commit history.',
    url='https://github.com/dxa4481/truffleHog',
    author='Modified by Jason Giedymin for ECRI, source originally from Dylan Ayrey',
    author_email='jgiedymin@ecri.org',
    license='GNU',
    packages=['truffleHogger'],
    install_requires=[
        'GitPython == 3.0.6'
    ],
    entry_points={
      'console_scripts': ['trufflehogger = truffleHogger.truffleHogger:main'],
    },
)
