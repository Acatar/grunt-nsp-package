grunt-nsp-package
=================
Audits your package.json file against the nodesecurity.io API for validation that dependencies or dependencies of dependencies are not vulnerable to known vulnerabilities.

[![Build Status](https://secure.travis-ci.org/nodesecurity/grunt-nsp-package.svg)](http://travis-ci.org/nodesecurity/grunt-nsp-package)
[![Dependency Status](https://david-dm.org/nodesecurity/grunt-nsp-package.png)](https://david-dm.org/nodesecurity/grunt-nsp-package)

## Getting Started

This plugin requires Grunt `~0.4.5`

If you haven't used [Grunt](http://gruntjs.com/) before, be sure to check out the [Getting Started](http://gruntjs.com/getting-started) guide, as it explains how to create a [Gruntfile](http://gruntjs.com/sample-gruntfile) as well as install and use Grunt plugins. Once you're familiar with that process, you may install this plugin with this command:

```shell
$ npm install grunt-nsp-package --save-dev
```

Once the plugin has been installed, it may be enabled inside your Gruntfile with this line of JavaScript:

```JavaScript
grunt.loadNpmTasks('grunt-nsp-package');
```

## NSP-Audit task
You can run this task with the `grunt nsp-audit` command. The command accepts an `-nsp-file` argument.

```shell
$ grunt nsp-audit -nsp-file "../some/other/app/package.json"
```

## Options
This package supports the following grunt config options:

* **file** (string): a single file to audit
* **files** (array): an array of files to audit
* **failBehavior** (string): whether or not to stop processing when an error or vulnerability is found. The options are `warn` or `log`. When only one file is being audited, `warn` is the default. When more than one file is being audited, `log` is the default.

This example audits a single package
```json
"nsp-audit": {
    "file": "../some/other/app/package.json",
    "failBehavior": "warn"
}
```

```json
"nsp-audit": {
    "file": ["../some/other/app/package.json", "../and/another/app/package.json"],
    "failBehavior": "log"
}
```

## Example

```JavaScript
module.exports = function (grunt) {
    'use strict';

    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json')
    });

    grunt.loadNpmTasks('grunt-nsp-package');

    grunt.config.set('nsp-package', {
        files: ['../some/other/app/package.json', '../and/another/app/package.json'],
        failBehavior: 'log'
    });

    grunt.registerTask('default', ['nsp-audit']);
};
```

## License
MIT
