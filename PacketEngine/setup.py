from setuptools import setup, find_packages
from os import path

loc = path.abspath(path.dirname(__file__))

with open(loc + '/requirements.txt') as f:
    requirements = f.read().splitlines()

required = []
dependency_links = []
EGG_MARK = '#egg='
for line in requirements:
    if line.startswith('-e git:') or line.startswith('-e git+') or \
            line.startswith('git:') or line.startswith('git+'):
        if EGG_MARK in line:
            #do nothing
            print()
            #package_name = line[line.find(EGG_MARK) + len(EGG_MARK):]
            #required.append(package_name)
            #dependency_links.append(line)
        else:
            print('Dependency to a git repository should have the format:')
            print('git+ssh://git@github.com/xxxxx/xxxxxx#egg=package_name')
    else:
        required.append(line)

setup(
    name='PacketEngine',
    version='1.0.0',
    description='This is PacketEngine',
    packages=find_packages(),
    install_requires=required,
    dependency_links=dependency_links,
)
