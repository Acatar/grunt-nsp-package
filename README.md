# grunt-nsp-package

Audits your package.json file against the nodesecurity.io API for validation that dependencies or dependencies of dependencies are not vulnerable to known vulnerabilities.

# Installation

    $ npm install grunt-nsp-package --save-dev

# Usage

Add this line to your project's grunt.js gruntfile:
```js
grunt.loadNpmTasks('grunt-nsp-package');
```

Then use the task `validate-package` or `validate-packages`, build tasks eg.
```js
grunt.registerTask("default", 'validate-package');
```

# Options

This package supports the following grunt config options:

* **file** (string): a single file to audit
* **files** (array): an array of files to audit
* **failBehavior** (string): whether or not to stop processing when an error or vulnerability is found. The options are `warn` or `log`. When only one file is being audited, `warn` is the default. When more than one file is being audited, `log` is the default.

This example audits a single package
```js
grunt.loadNpmTasks('grunt-nsp-package');

grunt.config.set('nsp-package', {
    file: '../some/other/app/package.json',
    failBehavior: 'warn'
});
```

This example audits multiple packages
```js
grunt.loadNpmTasks('grunt-nsp-package');

grunt.config.set('nsp-package', {
    files: ['../some/other/app/package.json', '../and/another/app/package.json'],
    failBehavior: 'log'
});
```

# License

MIT

# Badges

[![Build Status](https://secure.travis-ci.org/nodesecurity/grunt-nsp-package.svg)](http://travis-ci.org/nodesecurity/grunt-nsp-package)
[![Dependency Status](https://david-dm.org/nodesecurity/grunt-nsp-package.png)](https://david-dm.org/nodesecurity/grunt-nsp-package)
