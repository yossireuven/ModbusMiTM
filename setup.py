import io
import os
import re

from setuptools import find_packages
from setuptools import setup


def read(filename):
    filename = os.path.join(os.path.dirname(__file__), filename)
    text_type = type(u"")
    with io.open(filename, mode="r", encoding='utf-8') as fd:
        return re.sub(text_type(r':[a-z]+:`~?(.*?)`'), text_type(r'``\1``'), fd.read())


setup(
    name="Modbus_MiTM",
    version="0.1.1",
    url="https://github.com/yossireuven/Modbus_MiTM",
    license='BSD-3',

    author="Yossi Reuven",
    author_email="yossireuvens@gmail.com",

    description="Dynamic, learning MODBUS man-in-the-middle program.",
    long_description=read("README.rst"),

    packages=find_packages(exclude=('tests',)),

    install_requires=['numpy',
                      'numpy',
                      'numpy',
                      'numpy',
                      'numpy',
                      'numpy',
                      'numpy',
                      'scipy',
                      'scapy',
                      'PyYAML',
                      'psutil',
                      'psutil',
                      'yacs'],

    classifiers=[
        'Development Status :: Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
