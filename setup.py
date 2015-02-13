#!/usr/bin/python

import ez_setup
ez_setup.use_setuptools()

from setuptools import setup, find_packages
setup(
    name = "Statalysis",
    version = "0.1",
    packages = find_packages(),
)


