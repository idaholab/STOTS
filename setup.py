from setuptools import setup

# TODO
with open('requirements.txt') as f:
    requirements = f.read().splitlines()
setup(
    name='ConfigEngine',
    version='1.0',
    description='This is ConfigEngine.',
    author='Idaho National Laboratory',
    packages=['ConfigEngine'],
    install_requires=requirements
)
