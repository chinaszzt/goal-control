'use strict';

const { jest: jestObject } = require('@jest/globals');

globalThis.jest = jestObject;
delete process.env.NODE_PATH;
