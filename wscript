# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-


VERSION = "0.0.1"
APPNAME = "consumer"

from waflib import Logs, Utils, Context
import os

def options(opt):
    opt.load(['compiler_c', 'compiler_cxx', 'gnu_dirs'])
    opt.load(['boost', 'default-compiler-flags'],
             tooldir=['.waf-tools'])

    syncopt = opt.add_option_group ("CONSUMER Options")

    syncopt.add_option('--debug', action='store_true', default=False, dest='debug',
                       help='''debugging mode''')
    syncopt.add_option('--with-tests', action='store_true', default=False, dest='_tests',
                       help='''build unit tests''')

def configure(conf):
    conf.load(['compiler_c', 'compiler_cxx', 'gnu_dirs', 'boost', 'default-compiler-flags'])

    if 'PKG_CONFIG_PATH' not in os.environ:
        os.environ['PKG_CONFIG_PATH'] = Utils.subst_vars('${LIBDIR}/pkgconfig', conf.env)
    conf.check_cfg(package='libndn-cxx',args=['--cflags', '--libs'],
                   uselib_store='NDN_CXX', mandatory=True)
    conf.check_cfg(package='ndn-group-encrypt',args=['--cflags', '--libs'],
                   uselib_store='NDN-GROUP-ENCRYPT', mandatory=True)
    boost_libs = 'system iostreams'
    if conf.options._tests:
        conf.env['NDN_GEP_HAVE_TESTS'] = 1
        conf.define('NDN_GEP_HAVE_TESTS', 1);
        boost_libs += ' unit_test_framework'

    conf.check_boost(lib=boost_libs)

    conf.write_config_header('config.hpp')

def build(bld):
    bld(target="consumer-objects",
        name="consumer-objects",
        features=["cxx"],
        source=bld.path.ant_glob(['src/**/*.cpp'],
                                 excl=['src/main.cpp']),
        use='NDN_CXX BOOST NDN-GROUP-ENCRYPT',
        includes="src",
        export_includes="src",
        )

    bld(target="consumer",
        features=["cxx", "cxxprogram"],
        source=bld.path.ant_glob(['src/main.cpp']),
        use='consumer-objects',
        )
