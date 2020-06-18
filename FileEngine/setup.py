from setuptools import setup

with open('requirements.txt') as f:
    requirements = f.read().splitlines()
setup(
    name='FileEngine',
    version='1.0',
    description='This is FileEngine.',
    author='Idaho National Laboratory',
    install_requires=requirements
)
