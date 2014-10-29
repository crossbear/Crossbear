#!/usr/bin/python
from __future__ import with_statement
from fabric.api import *
import fabric

requirements_python = [{"package": 'dnspython', "require": 'dns'},
                       {"package": 'requests', "require": "requests"},
                       {"package": 'pyOpenSSL', "require": "OpenSSL"},
                       {"package": 'm2crypto', "require": "M2Crypto"},
                       {"package": 'pycrypto', "require": "Crypto"},
                       {"package": 'beautifulsoup', "require": "BeautifulSoup"}]

fabric.state.output.commands = False


@task
def install_pip():
    result = run("pip", quiet=True)
    if result.failed:
        run("[[ -f 'get-pip.py' ]] || wget -O get-pip.py 'https://bootstrap.pypa.io/get-pip.py'")
        sudo("python get-pip.py")


def fix_yum():
    result = sudo("""grep -E 'https|gpgcheck=1' /etc/yum.repos.d/*.repo""", quiet=True)
    if result.return_code == 0:
        # These yum sources do not seem to work, also keys are incorrect.
        sudo("sed -i.bak -e 'se/https/http/' -e 's/gpgcheck=1/gpgcheck=0/' /etc/yum.repos.d/*.repo")
        # Update only if we haven't before.
        sudo("yum update")
        sudo("yum upgrade -y")
        
@task
def install_deps():
    install_pip()
    fix_yum()
    sudo("yum install -y make automake gcc gcc-c++ kernel-devel openssl-devel libffi-devel swig")
    for req in requirements_python:
        result = run("python -c 'import %s'" % req["require"], pty=False, quiet=True)
        if result.failed:
            sudo("pip install %s" % req["package"])

@runs_once
@task
def create_tarball():
    local("rm -f /tmp/pybear.tar")
    local("git archive master > /tmp/pybear.tar")

@task
def deploy():
    execute(install_pip)
    execute(install_deps)
    execute(install_crossbear)

@task
def install_crossbear():
    execute(create_tarball)
    local("scp /tmp/pybear.tar %s:" % env.host_string)
    run("[[ -d PyBear ]] || mkdir PyBear")
    run("tar xvf pybear.tar -C PyBear")
    with cd("PyBear"):
        sudo("python -m py_compile PyBear.py")
    
    

# TODO Set up Cronjob
