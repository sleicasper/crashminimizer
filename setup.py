import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
        name="crashminimizer",
        version="0.0.1",
        author="Casper",
        license="MIT",
        author_email="slei.casper@gmail.com",
        description="A small example package",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/sleicasper/crashminimizer",
        packages = setuptools.find_packages(),
        include_package_data = True,
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
            ],
        entry_points = {
            'console_scripts': [
                'crashminimizer = crashminimizer.crashminimizer:main'
                ]
            },
        python_requires='>=3.6',
        )
