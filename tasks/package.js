var fs = require('fs');
var path = require('path');
var request = require('request');
var npmconf = require('npmconf');
var RegClient = require('npm-registry-client');
var semver = require('semver');
var async = require('async');
var googl = require('goo.gl');

var table = require('text-table');
var color = require('cli-color');
var ansiTrim = require('cli-color/lib/trim');

var registry;
var pkg;


module.exports = function (grunt) {
    var parents = {};
    var log;
    var warn;

    grunt.registerTask('validate-package', 'Audits package.json against nodesecurity.io API', function () {
        var done = this.async();
        var config = makeConfig(grunt.config.get('nsp-package'));

        log = function (message) {
            grunt.log.writeln(message);
        };

        warn = function (message) {
            if (config.failIfVulnerabilitiesFound) {
                grunt.fail.warn(message);
            } else {
                log(color.red(message));
            }
        };

        audit(config, done);
    });

    grunt.registerTask('validate-packages', ['validate-package']);

    function audit(config, done) {
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
                outputTasks.push(makeOutputTask(results[i].result, { file: results[i].file, fail: config.failIfVulnerabilitiesFound }));
            }

            printAuditOutput(outputTasks, config, done);
        });
    }

    function printAuditOutput(outputTasks, config, done) {
        log('');
        async.series(outputTasks, function (err, results) {
            if (err) {
                warn(err);
                return;
            }

            done();
        });
    }

    function makeConfig(config) {
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
    }

    function makeAuditTask (file) {
        return function (callback) {
            log(file);

            fs.exists(file, function (exists) {
                if (!exists) {
                    callback('Can\'t load ' + file);
                }
                pkg = JSON.parse(fs.readFileSync(file));
                npmconf.load(function (err, config) {
                    if (err) callback(err);

                    config.log = {
                        verbose: function () {},
                        info: function () {},
                        http: function () {},
                        silly: function () {},
                        error: function () {},
                        warn: function () {},
                    };
                    registry = new RegClient(config);
                    checkPackage(pkg, undefined, function (result) {
                        callback(null, { file: file, result: result});
                    });
                });
            });
        };
    }

    function makeOutputTask(result, options) {
        return function (callback) {
            prettyOutput(result, options, callback);
        };
    }

    function resolveParents(module, current) {
        current = current || [];
        var parent = parents[module] && parents[module].length ? parents[module][0] : undefined;
        if (parent && parent !== pkg.name && current.indexOf(parent) === -1) {
            current.unshift(parent);
            return resolveParents(parent, current);
        }
        return current;
    }

    function checkPackage(pkginfo, results, callback) {
        results = results || [];

        if (pkginfo.dependencies) {
            async.forEach(Object.keys(pkginfo.dependencies), function (module, cb) {

                parents[module] = parents[module] || [];
                if (parents[module].indexOf(pkginfo.name) === -1) {
                    parents[module].push(pkginfo.name);
                }

                registry.get(module, pkginfo.dependencies[module], function (er, data, raw, res) {
                    if (data && data.versions) {
                        var ver = semver.maxSatisfying(Object.keys(data.versions), pkginfo.dependencies[module]);
                        validateModule(module, ver, function (result) {
                            if (result) {
                                var d = {
                                    dependencyOf: resolveParents(module),
                                    module: module,
                                    version: ver,
                                    advisory: result[0]
                                };
                                results.push(d);
                            }
                            if (data && data.versions && data.versions[ver] && data.versions[ver].dependencies) {
                                checkPackage(data.versions[ver], results, function () {
                                    cb();
                                });
                            } else {
                                cb();
                            }
                        });
                    } else {
                        cb();
                    }
                });
            }, function (err) {
                callback(results);
            });
        }
    }

    function validateModule(module, version, cb) {
        var url = 'https://nodesecurity.io/validate/' + module + '/' + version;
        request({
            url: url,
            method: 'GET',
            headers: {
                'content-type': 'application/json'
            },
            json: true
        }, function (err, response, body) {
            if (body && body.length > 0) {
                return cb(body);
            }
            cb();
        });
    }

    function addResultRow(h, module) {
        h.push([
            module.module,
            module.version,
            module.advisory.patched_versions,
            module.dependencyOf.join(' > '),
            module.advisory.short_url || 'See website'
        ]);
    }

    function prettyOutputResults(result, h, callback) {
        var totalResults = result.length + 1;
        result.forEach(function (module) {
            if (!module.advisory.short_url) {
                googl.shorten('https://nodesecurity.io/advisories/' + module.advisory.url)
                    .then(function (shortUrl) {
                        module.advisory.short_url = shortUrl;
                        addResultRow(h, module);
                        if (h.length >= totalResults) callback();
                    })
                    .catch(function (error) {
                        addResultRow(h, module);
                        if (h.length >= totalResults) callback();
                    });
            } else {
                addResultRow(h, module);
                if (h.length >= totalResults) callback();
            }
        });
    }

    function prettyOutput(result, options, done) {
        options = options || {};

        if (result && result.length > 0) {
            // Pretty output
            var opts = {
                align: [ 'l', 'c', 'c', 'l', 'l' ],
                stringLength: function (s) { return ansiTrim(s).length; }
            };

            var h = [
                [
                    color.underline('Name'),
                    color.underline('Installed'),
                    color.underline('Patched'),
                    color.underline('Vulnerable Dependency'),
                    color.underline('Advisory URL')
                ]
            ];
            prettyOutputResults(result, h, function () {
                var t = table(h, opts);
                log(color.blue('results for: ' + options.file));
                log(color.white(t));
                warn('known vulnerable modules found');
                log('');

                done();
            });
        } else {
            log(color.green("No vulnerable modules found"));
            done();
        }
    }
};
