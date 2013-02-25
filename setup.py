from setuptools import setup, find_packages

setup(
    name="pyelliptic",
    version='1.5',
    url='https://github.com/yann2192/pyelliptic',
    license='GPL',
    description="Python OpenSSL wrapper. For modern cryptography with ECC, AES, HMAC, Blowfish, ...",
    author='Yann GUIBET',
    author_email='yannguibet@gmail.com',
    packages=find_packages(),
    classifiers=[
        'Operating System :: Unix',
        'Operating System :: Microsoft :: Windows',
        'Environment :: MacOS X',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security :: Cryptography',
    ],
)
