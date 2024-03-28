/* vi: set expandtab sw=4 sts=4: */
/* opkg.c - the opkg package management system

   Florian Boor
   Copyright (C) 2003 kernel concepts

   Carl D. Worth
   Copyright 2001 University of Southern California

   SPDX-License-Identifier: GPL-2.0-or-later

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   opkg command line frontend using libopkg
*/

#include "config.h"

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <locale.h>

#include "opkg_conf.h"
#include "opkg_cmd.h"
#include "file_util.h"
#include "opkg_message.h"
#include "opkg_download.h"
#include "xfuncs.h"

enum {
    ARGS_OPT_FORCE_MAINTAINER = 129,
    ARGS_OPT_IGNORE_MAINTAINER,
    ARGS_OPT_FORCE_DEPENDS,
    ARGS_OPT_FORCE_OVERWRITE,
    ARGS_OPT_FORCE_DOWNGRADE,
    ARGS_OPT_FORCE_REINSTALL,
    ARGS_OPT_FORCE_REMOVAL_OF_DEPENDENT_PACKAGES,
    ARGS_OPT_FORCE_REMOVAL_OF_ESSENTIAL_PACKAGES,
    ARGS_OPT_FORCE_SPACE,
    ARGS_OPT_FORCE_POSTINSTALL,
    ARGS_OPT_FORCE_REMOVE,
    ARGS_OPT_FORCE_CHECKSUM,
    ARGS_OPT_PREFER_ARCH_TO_VERSION,
    ARGS_OPT_ADD_ARCH,
    ARGS_OPT_ADD_DEST,
    ARGS_OPT_SIZE,
    ARGS_OPT_ADD_EXCLUDE,
    ARGS_OPT_ADD_IGNORE_RECOMMENDS,
    ARGS_OPT_NOACTION,
    ARGS_OPT_DOWNLOAD_ONLY,
    ARGS_OPT_NODEPS,
    ARGS_OPT_AUTOREMOVE,
    ARGS_OPT_VOLATILE_CACHE,
    ARGS_OPT_COMBINE,
    ARGS_OPT_INSTALL_RECOMMENDS,
    ARGS_OPT_NO_INSTALL_RECOMMENDS,
    ARGS_OPT_CACHE_DIR,
    ARGS_OPT_HOST_CACHE_DIR,
    ARGS_OPT_SHORT_DESCRIPTION,
    ARGS_OPT_FIELDS_FILTER,
    ARGS_OPT_RETRY_GET_LOCK,
};

static struct option long_options[] = {
    {"query-all", 0, 0, 'A'},
    {"autoremove", 0, 0, ARGS_OPT_AUTOREMOVE},
    {"conf-file", 1, 0, 'f'},
    {"conf", 1, 0, 'f'},
    {"combine", 0, 0, ARGS_OPT_COMBINE},
    {"dest", 1, 0, 'd'},
    {"force-maintainer", 0, 0, ARGS_OPT_FORCE_MAINTAINER},
    {"force_maintainer", 0, 0, ARGS_OPT_FORCE_MAINTAINER},
    {"ignore-maintainer", 0, 0, ARGS_OPT_IGNORE_MAINTAINER},
    {"ignore_maintainer", 0, 0, ARGS_OPT_IGNORE_MAINTAINER},
    {"force-depends", 0, 0, ARGS_OPT_FORCE_DEPENDS},
    {"force_depends", 0, 0, ARGS_OPT_FORCE_DEPENDS},
    {"force-overwrite", 0, 0, ARGS_OPT_FORCE_OVERWRITE},
    {"force_overwrite", 0, 0, ARGS_OPT_FORCE_OVERWRITE},
    {"force_downgrade", 0, 0, ARGS_OPT_FORCE_DOWNGRADE},
    {"force-downgrade", 0, 0, ARGS_OPT_FORCE_DOWNGRADE},
    {"force-reinstall", 0, 0, ARGS_OPT_FORCE_REINSTALL},
    {"force_reinstall", 0, 0, ARGS_OPT_FORCE_REINSTALL},
    {"force-space", 0, 0, ARGS_OPT_FORCE_SPACE},
    {"force_space", 0, 0, ARGS_OPT_FORCE_SPACE},
    {"force-removal-of-dependent-packages", 0, 0,
     ARGS_OPT_FORCE_REMOVAL_OF_DEPENDENT_PACKAGES},
    {"force_removal_of_dependent_packages", 0, 0,
     ARGS_OPT_FORCE_REMOVAL_OF_DEPENDENT_PACKAGES},
    {"force-removal-of-essential-packages", 0, 0,
     ARGS_OPT_FORCE_REMOVAL_OF_ESSENTIAL_PACKAGES},
    {"force_removal_of_essential_packages", 0, 0,
     ARGS_OPT_FORCE_REMOVAL_OF_ESSENTIAL_PACKAGES},
    {"force-postinstall", 0, 0, ARGS_OPT_FORCE_POSTINSTALL},
    {"force_postinstall", 0, 0, ARGS_OPT_FORCE_POSTINSTALL},
    {"force-remove", 0, 0, ARGS_OPT_FORCE_REMOVE},
    {"force_remove", 0, 0, ARGS_OPT_FORCE_REMOVE},
    {"force-checksum", 0, 0, ARGS_OPT_FORCE_CHECKSUM},
    {"force_checksum", 0, 0, ARGS_OPT_FORCE_CHECKSUM},
    {"prefer-arch-to-version", 0, 0, ARGS_OPT_PREFER_ARCH_TO_VERSION},
    {"prefer_arch_to_version", 0, 0, ARGS_OPT_PREFER_ARCH_TO_VERSION},
    {"noaction", 0, 0, ARGS_OPT_NOACTION},
    {"download-only", 0, 0, ARGS_OPT_DOWNLOAD_ONLY},
    {"nodeps", 0, 0, ARGS_OPT_NODEPS},
    {"install-recommends", 0, 0, ARGS_OPT_INSTALL_RECOMMENDS},
    {"no-install-recommends", 0, 0, ARGS_OPT_NO_INSTALL_RECOMMENDS},
    {"offline-root", 1, 0, 'o'},
    {"add-arch", 1, 0, ARGS_OPT_ADD_ARCH},
    {"add-dest", 1, 0, ARGS_OPT_ADD_DEST},
    {"size", 0, 0, ARGS_OPT_SIZE},
    {"add-exclude", 1, 0, ARGS_OPT_ADD_EXCLUDE},
    {"add-ignore-recommends", 1, 0, ARGS_OPT_ADD_IGNORE_RECOMMENDS},
    {"tmp-dir", 1, 0, 't'},
    {"tmp_dir", 1, 0, 't'},
    {"lists-dir", 1, 0, 'l'},
    {"lists_dir", 1, 0, 'l'},
    {"cache-dir", 1, 0, ARGS_OPT_CACHE_DIR},
    {"host-cache-dir", 0, 0, ARGS_OPT_HOST_CACHE_DIR},
    {"volatile-cache", 0, 0, ARGS_OPT_VOLATILE_CACHE},
    {"short-description", 0, 0, ARGS_OPT_SHORT_DESCRIPTION},
    {"fields", 1, 0, ARGS_OPT_FIELDS_FILTER},
    {"retry-get-lock", 0, 0, ARGS_OPT_RETRY_GET_LOCK},
    {"retry_get_lock", 0, 0, ARGS_OPT_RETRY_GET_LOCK},
    {"verbosity", 2, 0, 'V'},
    {"version", 0, 0, 'v'},
    {0, 0, 0, 0}
};

const char *short_options = "Ad:f:no:p:l:t:vV::";

static void store_str_arg(char **dest, const char *arg)
{
    free(*dest);
    *dest = xstrdup(arg);
}

/*
 * Performs stage 1 command line argument parsing.
 *
 * Stage 1 command line parsing handles all arguments that are required to parse
 * the configuration files.
 */
static int args_parse_stage1(int argc, char *argv[])
{
    int c;
    int option_index = 0;
    int parse_err = 0;
    char *solver_version = NULL;

    // Make sure that getopt starts from the beginning
    optind = 1;
    while (1) {
        c = getopt_long(argc, argv, short_options, long_options,
                             &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'f':
            opkg_config->conf_file = xstrdup(optarg);
            break;
        case 'o':
            opkg_config->offline_root = xstrdup(optarg);
            break;
        case 'v':
            solver_version = opkg_solver_version_alloc();
            if (solver_version) {
                printf("opkg version " VERSION " (%s)\n", solver_version);
                free(solver_version);
            } else {
                printf("opkg version " VERSION "\n");
            }
            exit(0);
        case 'V':
            opkg_config->verbosity = INFO;
            if (optarg != NULL)
                opkg_config->verbosity = atoi(optarg);
            break;
        case '?':
            parse_err = -1;
            break;
        default:
            // All other arguments are handled in stage 2 command line parsing.
            break;
        }
    }

    if (parse_err)
        return parse_err;
    else
        return optind;
}

/*
 * Performs stage 2 command line argument parsing.
 *
 * Stage 2 command line parsing handles all other arguments. Stage 2 parsing
 * is performed after the configuration files have been loaded thus allowing
 * configuration options to be overridden from the command line.
 */
static int args_parse_stage2(int argc, char *argv[])
{
    int c;
    int option_index = 0;
    int parse_err = 0;
    char *tuple, *targ;

    // Make sure that getopt starts from the beginning
    optind = 1;
    while (1) {
        c = getopt_long(argc, argv, short_options, long_options,
                             &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'A':
            opkg_config->query_all = 1;
            break;
        case 'd':
            store_str_arg(&opkg_config->dest_str, optarg);
            break;
        case 'o':
        case 'f':
        case 'v':
        case 'V':
            // Already handled in stage 1 command line parsing
            break;
        case 't':
            store_str_arg(&opkg_config->tmp_dir, optarg);
            break;
        case 'l':
            store_str_arg(&opkg_config->lists_dir, optarg);
            break;
        case ARGS_OPT_AUTOREMOVE:
            opkg_config->autoremove = 1;
            break;
        case ARGS_OPT_FORCE_MAINTAINER:
            opkg_config->force_maintainer = 1;
            break;
        case ARGS_OPT_IGNORE_MAINTAINER:
            opkg_config->ignore_maintainer = 1;
            break;
        case ARGS_OPT_FORCE_DEPENDS:
            opkg_config->force_depends = 1;
            break;
        case ARGS_OPT_FORCE_OVERWRITE:
            opkg_config->force_overwrite = 1;
            break;
        case ARGS_OPT_FORCE_DOWNGRADE:
            opkg_config->force_downgrade = 1;
            break;
        case ARGS_OPT_FORCE_REINSTALL:
            opkg_config->force_reinstall = 1;
            break;
        case ARGS_OPT_FORCE_REMOVAL_OF_ESSENTIAL_PACKAGES:
            opkg_config->force_removal_of_essential_packages = 1;
            break;
        case ARGS_OPT_FORCE_REMOVAL_OF_DEPENDENT_PACKAGES:
            opkg_config->force_removal_of_dependent_packages = 1;
            break;
        case ARGS_OPT_FORCE_SPACE:
            opkg_config->force_space = 1;
            break;
        case ARGS_OPT_FORCE_POSTINSTALL:
            opkg_config->force_postinstall = 1;
            break;
        case ARGS_OPT_FORCE_REMOVE:
            opkg_config->force_remove = 1;
            break;
        case ARGS_OPT_FORCE_CHECKSUM:
            opkg_config->force_checksum = 1;
            break;
        case ARGS_OPT_PREFER_ARCH_TO_VERSION:
            opkg_config->prefer_arch_to_version = 1;
            break;
        case ARGS_OPT_NODEPS:
            opkg_config->nodeps = 1;
            break;
        case ARGS_OPT_ADD_ARCH:
        case ARGS_OPT_ADD_DEST:
            tuple = xstrdup(optarg);
            if ((targ = strchr(tuple, ':')) != NULL) {
                *targ++ = 0;
                if ((strlen(tuple) > 0) && (strlen(targ) > 0)) {
                    nv_pair_list_append((c == ARGS_OPT_ADD_ARCH) ? &opkg_config->arch_list : &opkg_config->tmp_dest_list,
                                        tuple, targ);
                }
            }
            free(tuple);
            break;
        case ARGS_OPT_ADD_EXCLUDE:
            str_list_append(&opkg_config->exclude_list, optarg);
            break;
        case ARGS_OPT_ADD_IGNORE_RECOMMENDS:
            str_list_append(&opkg_config->ignore_recommends_list, optarg);
            break;
        case ARGS_OPT_SIZE:
            opkg_config->size = 1;
            break;
        case ARGS_OPT_NOACTION:
            opkg_config->noaction = 1;
            break;
        case ARGS_OPT_DOWNLOAD_ONLY:
            opkg_config->download_only = 1;
            break;
        case ARGS_OPT_CACHE_DIR:
            store_str_arg(&opkg_config->cache_dir, optarg);
            break;
        case ARGS_OPT_HOST_CACHE_DIR:
            opkg_config->host_cache_dir = 1;
            break;
        case ARGS_OPT_VOLATILE_CACHE:
            opkg_config->volatile_cache = 1;
            break;
        case ARGS_OPT_INSTALL_RECOMMENDS:
            opkg_config->no_install_recommends = 0;
            break;
        case ARGS_OPT_NO_INSTALL_RECOMMENDS:
            opkg_config->no_install_recommends = 1;
            break;
        case ARGS_OPT_SHORT_DESCRIPTION:
           opkg_config->short_description = 1;
           break;
        case ARGS_OPT_FIELDS_FILTER:
            store_str_arg(&opkg_config->fields_filter, optarg);
            break;
        case ARGS_OPT_RETRY_GET_LOCK:
            store_str_arg(&opkg_config->retry_get_lock = 1);
            break;
        case ARGS_OPT_COMBINE:
            opkg_config->combine = 1;
            break;
        default:
            fprintf(stderr, "Encountered unhandled option %d during command line parsing\n", c);
        }
    }

    if (parse_err)
        return parse_err;
    else
        return optind;
}

static void usage()
{
    printf("usage: opkg [options...] sub-command [arguments...]\n");
    printf("where sub-command is one of:\n");

    printf("\nPackage Manipulation:\n");
    printf("\tupdate                          Update list of available packages\n");
    printf("\tupgrade                         Upgrade installed packages\n");
    printf("\tdist-upgrade                    Upgrade operation that allows package removal (libsolv backend)\n");
    printf("\tinstall <pkgs>                  Install package(s)\n");
    printf("\tconfigure <pkgs>                Configure unpacked package(s)\n");
    printf("\tremove <pkgs|glob>              Remove package(s)\n");
    printf("\tclean                           Clean internal cache\n");
    printf("\tflag <flag> <pkgs>              Flag package(s)\n");
    printf("\t <flag>=hold|noprune|user|ok|installed|unpacked (one per invocation)\n");

    printf("\nInformational Commands:\n");
    printf("\tlist                            List available packages\n");
    printf("\tlist-installed                  List installed packages\n");
    printf("\tlist-upgradable                 List installed and upgradable packages\n");
    printf("\tlist-changed-conffiles          List user modified configuration files\n");
    printf("\tfiles <pkg>                     List files belonging to <pkg>\n");
    printf("\tsearch <file|glob>              List package providing <file>\n");
    printf("\tfind <regexp>                   List packages with names or description matching <regexp>\n");
    printf("\tinfo [pkg|glob]                 Display all info for <pkg>\n");
    printf("\tstatus [pkg|glob]               Display all status for <pkg>\n");
    printf("\tdownload <pkg>                  Download <pkg> to current directory\n");
    printf("\tcompare-versions <v1> <op> <v2>\n");
    printf("\t                                compare versions using <= < > >= = << >>\n");
    printf("\tprint-architecture              List installable package architectures\n");
    printf("\tdepends [-A] [pkgname|glob]+\n");
    printf("\twhatdepends [-A] [pkgname|glob]+\n");
    printf("\twhatdependsrec [-A] [pkgname|glob]+\n");
    printf("\twhatrecommends[-A] [pkgname|glob]+\n");
    printf("\twhatsuggests[-A] [pkgname|glob]+\n");
    printf("\twhatprovides [-A] [pkgname|glob]+\n");
    printf("\twhatconflicts [-A] [pkgname|glob]+\n");
    printf("\twhatreplaces [-A] [pkgname|glob]+\n");
    printf("\tverify [pkg|glob]               Verifies the integrity of <pkg>, or all packages if omitted by\n");
    printf("\t                                comparing the md5sum of each file with the information stored\n");
    printf("\t                                on the opkg metadata database\n");
    printf("\t-v, --version                   Print version\n");
    printf("\nOptions:\n");
    printf("\t-A                              Query all packages not just those installed\n");
    printf("\t-V[<level>]                     Set verbosity level to <level>.\n");
    printf("\t--verbosity[=<level>]           Verbosity levels:\n");
    printf("\t                                  0 errors only\n");
    printf("\t                                  1 normal messages (default)\n");
    printf("\t                                  2 informative messages\n");
    printf("\t                                  3 debug\n");
    printf("\t                                  4 debug level 2\n");
    printf("\t-f <conf_file>                  Use <conf_file> as the opkg configuration file\n");
    printf("\t--conf <conf_file>\n");
    printf("\t--cache-dir <path>              Specify cache directory.\n");
    printf("\t-t, --tmp-dir <directory>       Specify tmp-dir.\n");
    printf("\t-l, --lists-dir <directory>     Specify lists-dir.\n");
    printf("\t-d <dest_name>                  Use <dest_name> as the the root directory for\n");
    printf("\t--dest <dest_name>              package installation, removal, upgrading.\n");
    printf("\t                                <dest_name> should be a defined dest name from\n");
    printf("\t                                the configuration file, (but can also be a\n");
    printf("\t                                directory name in a pinch).\n");
    printf("\t-o <dir>                        Use <dir> as the root directory for\n");
    printf("\t--offline-root <dir>            offline installation of packages.\n");
    printf("\t--add-dest <name>:<path>        Register destination with given path\n");
    printf("\t--add-arch <arch>:<prio>        Register architecture with given priority\n");
    printf("\t--add-exclude <name>            Register package to be excluded from install\n");
    printf("\t--add-ignore-recommends <name>  Register package to be ignored as a recomendee\n");
    printf("\t--prefer-arch-to-version        Use the architecture priority package rather\n");
    printf("\t                                than the higher version one if more\n");
    printf("\t                                than one candidate is found.\n");
    printf("\t--combine                       Combine upgrade and install operations, this\n");
    printf("\t                                may be needed to resolve dependency issues.\n");
    printf("\t                                Only available for the internal solver backend.\n");
    printf("\t--fields <field1>,<field2>      Limit display information to the specified fields\n");
    printf("\t                                plus the package name. Valid for info and status.\n");
    printf("\t--short-description             Display only the first line of the description.\n");
    printf("\t--size                          Print package size when listing available packages\n");

    printf("\nForce Options:\n");
    printf("\t--force-depends                 Install/remove despite failed dependencies\n");
    printf("\t--force-maintainer              Overwrite preexisting config files\n");
    printf("\t--force-reinstall               Reinstall package(s)\n");
    printf("\t--force-overwrite               Overwrite files from other package(s)\n");
    printf("\t--force-downgrade               Allow opkg to downgrade packages\n");
    printf("\t--force-space                   Disable free space checks\n");
    printf("\t--force-postinstall             Run postinstall scripts even in offline mode\n");
    printf("\t--force-remove                  Remove package even if prerm script fails\n");
    printf("\t--force-checksum                Don't fail on checksum mismatches\n");
    printf("\t--noaction                      No action -- test only\n");
    printf("\t--download-only                 No action -- download only\n");
    printf("\t--nodeps                        Do not follow dependencies\n");
    printf("\t--[no-]install-recommends       (Do not) install any recommended packages\n");
    printf("\t--force-removal-of-dependent-packages\n");
    printf("\t                                Remove package and all dependencies\n");
    printf("\t--autoremove                    Remove packages that were installed\n");
    printf("\t                                automatically to satisfy dependencies\n");
    printf("\t--host-cache-dir                Don't place cache in offline root dir.\n");
    printf("\t--volatile-cache                Use volatile cache.\n");
    printf("\t                                Volatile cache will be cleared on exit\n")j;
    printf("\t--retry-get-lock                Allow retry if we fail to get lock file.\n");
    printf("\t                                This helps with systemd postinsts service.\n");
    printf("\n");

    printf(" glob could be something like 'pkgname*' '*file*' or similar\n");
    printf(" e.g. opkg info 'libstd*' or opkg search '*libop*' or opkg remove 'libncur*'\n");

    /* --force-removal-of-essential-packages        Let opkg remove essential packages.
     * Using this option is almost guaranteed to break your system, hence this option
     * is not even advertised in the usage statement. */

    exit(1);
}

int main(int argc, char *argv[])
{
    int opts, err = -1;
    char *cmd_name = NULL;
    opkg_cmd_t *cmd;
    int nocheckfordirorfile;
    int noreadfeedsfile;
    int noloadconf;

    if (opkg_conf_init())
        goto err0;

    setlocale(LC_ALL, "");
    opkg_config->verbosity = NOTICE;

    opts = args_parse_stage1(argc, argv);
    if (opts == argc || opts < 0) {
        fprintf(stderr, "opkg must have one sub-command argument\n");
        usage();
    }

    cmd_name = argv[opts++];

    nocheckfordirorfile = !strcmp(cmd_name, "print-architecture")
        || !strcmp(cmd_name, "print_architecture")
        || !strcmp(cmd_name, "print-installation-architecture")
        || !strcmp(cmd_name, "print_installation_architecture")
        || !strcmp(cmd_name, "compare_versions")
        || !strcmp(cmd_name, "compare-versions")
        || !strcmp(cmd_name, "clean");

    noreadfeedsfile = !strcmp(cmd_name, "flag")
        || !strcmp(cmd_name, "configure")
        || !strcmp(cmd_name, "remove")
        || !strcmp(cmd_name, "files")
        || !strcmp(cmd_name, "search")
        || !strcmp(cmd_name, "list_installed")
        || !strcmp(cmd_name, "list-installed")
        || !strcmp(cmd_name, "list_changed_conffiles")
        || !strcmp(cmd_name, "list-changed-conffiles")
        || !strcmp(cmd_name, "status")
        || !strcmp(cmd_name, "clean");

    noloadconf = !strcmp(cmd_name, "compare_versions")
        || !strcmp(cmd_name, "compare-versions");

    cmd = opkg_cmd_find(cmd_name);
    if (cmd == NULL) {
        fprintf(stderr, "%s: unknown sub-command %s\n", argv[0], cmd_name);
        usage();
    }

    opkg_config->pfm = cmd->pfm;

    if (!noloadconf) {
        if (opkg_conf_read())
            goto err0;
    }

    if (args_parse_stage2(argc, argv) < 0) {
        fprintf(stderr, "Stage 2 argument parsing failed.\n");
        usage();
    }

    if (!noloadconf) {
        if (opkg_conf_finalize())
            goto err0;
    }

    if (!nocheckfordirorfile) {
        if (!noreadfeedsfile) {
            if (pkg_hash_load_feeds())
                goto err1;
        }

        if (pkg_hash_load_status_files())
            goto err1;
    }

    if (cmd->requires_args && opts == argc) {
        fprintf(stderr, "%s: the ``%s'' command requires at least one argument\n",
                argv[0], cmd_name);
        usage();
    }

    err = opkg_cmd_exec(cmd, argc - opts, (const char **)(argv + opts));

    opkg_download_cleanup();
 err1:
    opkg_conf_deinit();

 err0:
    return err;
}
