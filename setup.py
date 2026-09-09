from setuptools import setup, find_packages

setup(
    name="reconfox",
    version="2.0.0",
    description="Reconfox — concurrent, modular reconnaissance suite by MixerMiner & Anonymous-beta & samuelanih043-droid",
    author="MixerMiner & Anonymous-beta & samuelanih043-droid",
    packages=find_packages(),
    include_package_data=True,
    package_data={"reconfox": ["data/*.txt"]},
    install_requires=[
        "rich>=13.7.0",
        "httpx[http2]>=0.27.0",
        "dnspython>=2.6.0",
    ],
    entry_points={"console_scripts": ["reconfox=reconfox.cli:main"]},
    python_requires=">=3.9",
)
