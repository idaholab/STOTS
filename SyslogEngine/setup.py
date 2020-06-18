from setuptools import setup

with open('requirements.txt') as f:
    requirements = f.read().splitlines()
setup(
    name='SyslogEngine',
    version='1.0',
    description='This is SyslogEngine.',
    author='Idaho National Laboratory',
    install_requires=requirements
)
