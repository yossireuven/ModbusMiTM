Modbus_MiTM
===========

.. image:: https://img.shields.io/pypi/v/Modbus_MiTM.svg
    :target: https://pypi.python.org/pypi/Modbus_MiTM
    :alt: Latest PyPI version

.. image:: https://travis-ci.org/borntyping/cookiecutter-pypackage-minimal.png
   :target: https://travis-ci.org/borntyping/cookiecutter-pypackage-minimal
   :alt: Latest Travis CI build status

Dynamic, learning MODBUS man-in-the-middle program.

Why
-----
The idea behind this project is to exploit the basic
assumption that ICS communications (HMI<->Sensors) mostly
have deterministic behavior which can be represent as functions
that will describe each Sensor registers (process behavior over time).

The ability to predict Sensors value with good accuracy over a period of time
can help in many areas - process automation, error/bugs/fault predictions and more.

What
-----
In this POC the target will be to emulate the field component value while attacking
the HMI with Man-in-The-Middle (MiTM) using ARP spoofing. The program will first "learn"
the sensor usual value over period of time, then will create a function using `Spline Interpolation`_.

.. _Spline Interpolation: https://docs.scipy.org/doc/scipy/reference/generated/scipy.interpolate.UnivariateSpline.html

The project include all end-to-end components:

* ARP Spoofing.
* Session Hijacking.
* Data interpolation.
* Network tools.
* Assets discovery (WIP)

How
-----
**Edit $APP_HOME/config/defaults.py**

learn model and attack::

    python3 main.py -l -a


attack using stored model::

    python3 main.py -a -m MODEL_NAME

list stored models::

    python3 main.py -L

learn and store model::

    python3 main.py -l

plot model registers graphs::

    python3 main.py -p -m MODEL_NAME


Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -l LEARN, --learn=LEARN
                        learn and interpolate over traffic
  -a, --attack          run attack using learned model
  -m LOAD_MODEL, --model=LOAD_MODEL
                        load saved model
  -p, --plot            plot saved model functions
  -d DISCOVER, --discover=DISCOVER
                        assets discovery
  -L LIST, --list=LIST  list saved models


Installation
------------
    python3 setup.py install


Requirements
^^^^^^^^^^^^
python3-tk

Compatibility
-------------
Tested on:

* Kali Linux 2018.4
* Ubuntu 18.04

Licence
-------
BSD 3

Authors
-------

`Modbus_MiTM` was written by `Yossi Reuven <yossireuvens@gmail.com>`_ - NEC Israel Research Center.
