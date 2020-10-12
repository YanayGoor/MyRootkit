from setuptools import setup

setup(
    name="rootkit-client",
    version="0.0.1",
    author="yanayg",
    author_email="yanay.goor@gmail.com",
    description="Client for sending remote commands to a rootkit",
    url="https://github.com/YanayGoor/MyRootkit",
    python_requires='>=3.7',
    entry_points={
        'console_scripts': ['rootkit-client=client:main'],
    }
)
