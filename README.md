grunt-nsp-package
=================
This package is a grunt extension of the nsp package, which enables developers or CI tools to check if their Node.js projects are using packages with known and public vulnerable dependencies. The vulnerability database is provided by the [Node Security Project](https://nodesecurity.io).

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
You can run this task with the `grunt nsp-audit` command. The command accepts an `-nsp-file` argument. If you omit the `-nsp-file` argument, it will audit the `package.json` file in the immediate folder.

```shell
$ grunt nsp-audit -nsp-file "../some/other/app/package.json"
```

## Options
This package supports the following grunt config options:

* **file** (string): a single file to audit (this argument is ignored if **files** has a value)
* **files** (array): an array of files to audit
* **failBehavior** (string): whether or not to stop processing when an error or vulnerability is found. The options are `warn` or `log`. When only one file is being audited, `warn` is the default. When more than one file is being audited, `log` is the default.

This example configuration audits a single package
```json
"nsp-audit": {
    "file": "../some/other/app/package.json",
    "failBehavior": "warn"
}
```

This example configuration audits multiple packages
```json
"nsp-audit": {
    "files": ["../some/other/app/package.json", "../and/another/app/package.json"],
    "failBehavior": "log"
}
```

## Example

```JavaScript
// gruntfile.js
module.exports = function (grunt) {
    'use strict';

    grunt.initConfig({
        pkg: grunt.file.readJSON('package.json')
    });

    grunt.loadNpmTasks('grunt-nsp-package');

    grunt.config.set('nsp-audit', {
        files: ['../some/other/app/package.json', '../and/another/app/package.json'],
        failBehavior: 'log'
    });

    grunt.registerTask('default', ['nsp-audit']);
};
```

## License
MIT
