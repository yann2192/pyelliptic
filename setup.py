import os
import re
import codecs
from setuptools import setup, find_packages

def read(*parts):
    return codecs.open(os.path.join(os.path.dirname(__file__), *parts)).read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

setup(
    name="pyelliptic",
    version=find_version("pyelliptic", "__init__.py"),
    url='https://github.com/yann2192/pyelliptic',
    license='GPL',
    description="Python OpenSSL wrapper. For modern cryptography with ECC, AES, HMAC, Blowfish, ...",
    long_description=read('README'),
    author='Yann GUIBET',
    author_email='yannguibet@gmail.com',
    packages=find_packages(),
    classifiers=[
        'Operating System :: Unix',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security :: Cryptography',
    ],
)
