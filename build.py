#!/usr/bin/env /usr/bin/python
""" Coordinates the tasks of refreshing the configuration (i.e. version.cfg) """
import os, re
import subprocess
import ConfigParser
#from pprint import pprint


VERSION_SECTION = 'vers'


class VersionUpdater(object):
    """ Updates the version config for the files in the static directory """
    def __init__(self, appname):
        """ Creates new instance of VersionUpdater

        :param appname: the directory name for the app's current working directory
        """
        self.exepath = '%s' % (os.path.dirname(os.path.realpath(__file__)))
        self.cnfgfile = '%s/versions.cfg' % self.exepath
        self.static_path = '%s/app/static' % self.exepath
        self.config = ConfigParser.RawConfigParser()

    def init_config(self):
        """ Preps the config file safely (so other sections stay) """
        #self.config.read(self.cnfgfile)
        if not self.config.has_section(VERSION_SECTION):
            self.config.add_section(VERSION_SECTION)

    def run(self):
        """ Executes the job """
        self.init_config()
        files = self.list_files()
        #pprint(files)
        update = False
        for fullpath in files:
            #print 'fullpath is %s' % fullpath
            infile = os.path.basename(fullpath)
            version = subprocess.check_output(['sha1sum', fullpath]).split()[0]
            version = version[0:8]
            if version:
                self.config.set(VERSION_SECTION, infile, version)
                update = True
        if update:
            with open(self.cnfgfile, 'wb') as configfile:
                self.config.write(configfile)

    def list_files(self):
        """ Iterates recursively through the static folder and
            returns a list of the files in it.
        """
        re_css = re.compile(r'\.css$')
        re_js = re.compile(r'\.js$')
        re_adminlte2 = re.compile(r'adminlte2')
        file_list = []
        print "static path is %s" % self.static_path
        for dirpath, _, files in os.walk(self.static_path):
            if not re_adminlte2.search(dirpath):
                for name in files:
                    if re_css.search(name) or re_js.search(name):
                        file_list.append(os.path.join(dirpath, name))
        return file_list


def main():
    """ Main entry point for build.py """
    updater = VersionUpdater('PowerDNS-Admin')
    updater.run()


if __name__ == '__main__':
    main()
