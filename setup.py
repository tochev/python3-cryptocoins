#!/usr/bin/env python3
import os
from setuptools import setup

def read(fname):
    # Utility function to read the README file.
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "cryptocoins",
    version = "0.0.1",
    author = "Tocho Tochev",
    author_email = "tocho@tochev.net",
    description = ("library for manipulating crypto currency addresses"),
    license = "MIT",
    keywords = "cryptocurrency bitcoin litecoin dogecoin btc ltc",
    url = "https://github.com/tochev/python3-cryptocoins",
    packages=['cryptocoins'],
    scripts=['bin/generate-coin-address'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Topic :: Utilities",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    install_requires=read('requirements.txt').strip().splitlines(),
)
