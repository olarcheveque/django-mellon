#! /usr/bin/env python

''' Setup script for mellon
'''

import os
import subprocess
from setuptools import setup, find_packages
from setuptools.command.install_lib import install_lib as _install_lib
from distutils.command.build import build as _build
from setuptools.command.sdist import sdist as _sdist
from distutils.cmd import Command


class compile_translations(Command):
    description = 'compile message catalogs to MO files via django compilemessages'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import os
        from django.core.management import call_command
        os.environ.pop('DJANGO_SETTINGS_MODULE', None)
        for path in ['mellon/']:
            if path.endswith('.py'):
                continue
            curdir = os.getcwd()
            os.chdir(os.path.realpath(path))
            call_command('compilemessages')
            os.chdir(curdir)


class build(_build):
    sub_commands = [('compile_translations', None)] + _build.sub_commands


class eo_sdist(_sdist):
    sub_commands = [('compile_translations', None)] + _build.sub_commands

    def run(self):
        print("creating VERSION file")
        if os.path.exists('VERSION'):
            os.remove('VERSION')
        version = get_version()
        version_file = open('VERSION', 'w')
        version_file.write(version)
        version_file.close()
        _sdist.run(self)
        print("removing VERSION file")
        if os.path.exists('VERSION'):
            os.remove('VERSION')


class install_lib(_install_lib):
    def run(self):
        self.run_command('compile_translations')
        _install_lib.run(self)


def get_version():
    '''Use the VERSION, if absent generates a version with git describe, if not
       tag exists, take 0.0.0- and add the length of the commit log.
    '''
    if os.path.exists('VERSION'):
        with open('VERSION', 'r') as v:
            return v.read()
    if os.path.exists('.git'):
        p = subprocess.Popen(['git', 'describe', '--dirty', '--match=v*'], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        result = p.communicate()[0]
        if p.returncode == 0:
            return result.decode('ascii').split()[0][1:].replace('-', '.')
        else:
            return '0.0.0-%s' % len(subprocess.check_output(
                ['git', 'rev-list', 'HEAD']).splitlines())
    return '0.0.0'

setup(name="django-mellon",
      version=get_version(),
      license="AGPLv3 or later",
      description="SAML 2.0 authentication for Django",
      long_description=open('README').read(),
      url="http://dev.entrouvert.org/projects/django-mellon/",
      author="Entr'ouvert",
      author_email="info@entrouvert.org",
      include_package_data=True,
      packages=find_packages(),
      install_requires=[
          'django>=1.5,<2.0',
          'requests',
          'isodate',
      ],
      setup_requires=[
          'django',
      ],
      tests_require=[
          'nose>=0.11.4',
      ],
      dependency_links=[],
      cmdclass={
          'build': build,
          'install_lib': install_lib,
          'compile_translations': compile_translations,
          'sdist': eo_sdist,
      })
