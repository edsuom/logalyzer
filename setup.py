#!/usr/bin/python

import ez_setup
ez_setup.use_setuptools()

from setuptools import setup, find_packages
setup(
    name = "Statalysis",
    version = "0.3",
    packages = find_packages(),
    entry_points = {
        'console_scripts': [
            'sa = statalysis.main:run'],
    }
)


