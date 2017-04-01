from setuptools import find_packages, setup

setup(
    name='python-nuki-client',
    version='0.1.3',
    license='GPL3',
    description='Python library for Nuki KT',
    author='Tobias Feistmantl / Jan De Beule',
    author_email='tobias@myhome-automations.com',
    url='https://github.com/MyHomeAutomations/python-nuki-client',
    packages=find_packages(),
    install_requires=['pygatt', 'pynacl', 'crc16', 'pybluez', 'pexpect']
)