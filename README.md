Flask Kerberos Authentication
=============================

Based on [flask-kerberos](https://github.com/mkomitee/flask-kerberos). If you
only require Kerberos authentication, that library works great!

This library is meant to integrate with
[flask-login](https://github.com/maxcountryman/flask-login) to avoid declaring
in the application code the dependency on Kerberos.

Testing
=======

Run the unit-tests:

```sh
python setup.py develop
pip install -r dev-requirements.txt
python -m unittest discover
```

Follow the instructions at
[dsludwig/kerberos_test](https://github.com/dsludwig/kerberos_test)
to set up a test environment.

SSH into the client machine to begin configuration.

```sh
vagrant ssh client
```

Inside the ssh session:

```sh
# Install miniconda
wget https://repo.continuum.io/miniconda/Miniconda-latest-Linux-x86_64.sh
bash Miniconda-latest-Linux-x86_64.sh
```

Create a new ssh session, and execute the following commands:

```sh
# Install the library
conda create -n flask_kerberos_test -c binstar flask-kerberos-login

# Activate the environment
source activate flask_kerberos_test

# Get the example code
wget https://raw.githubusercontent.com/ContinuumIO/flask-kerberos-login/master/examples/simple.py

# Execute the server
KRB5_KTNAME=/vagrant/http.keytab python simple.py
```

Now authenticate with the KDC and access the test site:
```sh
kinit admin
curl --negotiate -u : client.example.com:5000
```

License
=======

Copyright © 2016, Continuum Analytics under the [BSD 2-Clause
license](https://opensource.org/licenses/BSD-2-Clause).
