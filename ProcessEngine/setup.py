from setuptools import setup

with open('requirements.txt') as f:
    requirements = f.read().splitlines()
setup(
    name='ProcessEngine',
    version='1.0',
    description='This is ProcessEngine.',
    author='Idaho National Laboratory',
    install_requires=requirements
)
