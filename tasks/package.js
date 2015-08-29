var grunt = require('grunt'),
    auditPackage = require('nsp/lib/auditPackage.js'),
    path = require('path'),
    async = require('async'),
    chalk = require('chalk'),
    table = require('text-table');

module.exports = function (grunt) {
    var makeConfig,
        makeAuditTask,
        makeOutputTask,
        audit,
        printAuditOutput,
        prettyOutput,
        log,
        warn;

    /*
    // Takes the grunt config, if any, and normalizes it into a config model with defaults being set.
    // @param config (Object): the raw config for nsp-package from grunt
    // @returns (Object): normalized config model with defaults being set
    */
    makeConfig = function (config) {
        var failOptIsBoolean;

        config = config || {};

        // ensure that a config.files value exists and is an array
        if (typeof config.file === 'string' && !Array.isArray(config.files)) {
            config.files = [config.file];
        } else if (typeof config.files === 'string') {
            config.files = [config.files];
        } else if (!Array.isArray(config.files)) {
            config.files = [path.resolve(process.cwd(), 'package.json')];
        }

        // respect configuration override, but set the default "fail"
        // behavior to true if the files array has only one file,
        // otherwise set it to false
        if (config.failBehavior === 'warn') {
            config.failIfVulnerabilitiesFound = true;
        } else if (config.failBehavior === 'log') {
            config.failIfVulnerabilitiesFound = false;
        } else if (config.files.length === 1) {
            config.failIfVulnerabilitiesFound = true;
        } else {
            config.failIfVulnerabilitiesFound = false;
        }

        return config;
    };

    /*
    // Makes an async task for auditing a single package.json file
    // @param file (String): the file-path for the package.json that is being audited
    // @returns (Function): the async task
    */
    makeAuditTask = function (file) {
        return function (callback) {
            log(file);
            auditPackage(file, function (err, result) {
                callback(err, { file: file, result: result });
            });
        };
    };

    /*
    // Makes an async task for printing the result for a single audit
    // @param result (Array): The results from the audit
    // @param options (Object): options for printing, which should include at a minimum, the name of the file
    // @returns (Function): the async task
    */
    makeOutputTask = function (result, options) {
        return function (callback) {
            prettyOutput(result, options, callback);
        };
    };

    /*
    // Orchestrates the auditing
    // @param config (Object): The grunt config, already having been processed to set defaults
    // @param done (Function): The grunt async done callback
    */
    audit = function (config, done) {
        var tasks = [];
        var outputTasks = [];
        var i;

        for (i = 0; i < config.files.length; i += 1) {
            tasks.push(makeAuditTask(config.files[i]));
        }
        log('Checking package(s) for known vulnerabilities:');

        async.parallel(tasks, function (err, results) {
            var i;

            if (err) {
                warn(err);
                return;
            }

            for (i = 0; i < results.length; i += 1) {
                outputTasks.push(makeOutputTask(results[i].result, results[i].file));
            }

            printAuditOutput(outputTasks, config, done);
        });
    };

    /*
    // Orchestrates printing of the output of all audit results to the console
    // @param outputTasks (Array): the tasks that will print to the console
    // @param config (Object): The grunt config, already having been processed to set defaults
    // @param done (Function): The grunt async done callback
    */
    printAuditOutput = function (outputTasks, config, done) {
        log('');
        async.series(outputTasks, function (err, results) {
            if (err) {
                warn(err);
                return;
            }

            done();
        });
    };

    /*
    // Prints the results to the console
    // @param result (Array): The vulnerability results, if any
    // @param file (String): The filePath these results are for
    // @param callback (Function): the async callback to signal completion
    */
    prettyOutput = function (result, file, callback) {
        var opts, headings;

        if (result && result.length > 0) {
            // Pretty output
            opts = {
                align: ['l', 'c', 'c', 'l'],
                stringLength: function(s) {
                    return chalk.stripColor(s).length;
                }
            };
            headings = [
                [
                    chalk.underline('Name'),
                    chalk.underline('Installed'),
                    chalk.underline('Patched'),
                    chalk.underline('Vulnerable Dependency')
                ]
            ];

            result.forEach(function(module) {
                headings.push([
                    module.module,
                    module.version,                   /* jscs:disable */
                    module.advisory.patched_versions,
                    module.dependencyOf.join(' > ')   /* jscs:enable */
                ]);
            });
            log(chalk.blue('results for: ' + file));
            log(table(headings, opts));
            warn('known vulnerable modules found');
            log('');
            callback();
        } else {
            log(chalk.green('No vulnerable modules found for: ' + file));
            log('');
            callback();
        }
    };

    /*
    // The main grunt task
    */
    grunt.registerTask('nsp-audit', 'Audits package.json against nodesecurity.io API', function () {
        var done = this.async(),
            config = makeConfig(grunt.config.get('nsp-package')),
            file = grunt.option('nsp-file');

        if (file) {
            config.files = [file];
        }

        log = function (message) {
            grunt.log.writeln(message);
        };

        warn = function (message) {
            if (config.failIfVulnerabilitiesFound) {
                grunt.fail.warn(message);
            } else {
                log(chalk.red(message));
            }
        };

        audit(config, done);
    });

    /*
    // Backwards compatibility
    */
    grunt.registerTask('validate-package', ['nsp-audit']);
};
