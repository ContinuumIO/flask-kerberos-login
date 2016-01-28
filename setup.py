from setuptools import setup, find_packages
import versioneer

setup(
    name='flask-kerberos-login',
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    author='Continuum Analytics',
    author_email='dludwig@continuum.io',
    url='http://github.com/ContinuumIO/flask-kerberos-login',
    description='Kerberos authentication compatible with flask-login',
    packages=find_packages(),
    install_requires=[
        'flask',
        'flask-login',
        'pykerberos',
    ],
)

