import os
import sys
try:
    import unittest2 as unittest
except ImportError:
    import unittest

cpath = os.path.dirname(os.path.realpath(__file__))
# alter path so we can import cli
abrtcli_path = os.path.abspath(os.path.join(cpath, "../.."))
problem_path = os.path.abspath(os.path.join(cpath, "../../../python-problem"))
pyabrt_path = os.path.join(problem_path, "problem/.libs")  # because of _pyabrt
sys.path.insert(0, abrtcli_path)
sys.path.insert(0, problem_path)
sys.path.insert(0, pyabrt_path)
os.environ["PATH"] = "{0}:{1}".format(abrtcli_path, os.environ["PATH"])

import problem
from .fake_problems import get_fake_problems

problem.list = get_fake_problems


class TestCase(unittest.TestCase):
    """
    Class that initializes required configuration variables.
    """

    pass
