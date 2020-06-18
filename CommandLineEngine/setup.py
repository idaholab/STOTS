from setuptools import setup

with open('requirements.txt') as f:
    requirements = f.read().splitlines()
setup(
    name='CommandLineEngine',
    version='1.0',
    description='This is CommandLineEngine.',
    author='Idaho National Laboratory',
    install_requires=requirements
)
