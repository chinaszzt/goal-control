'use strict';

class ControlError extends Error {
  constructor(code, message, details = null) {
    super(message);
    this.name = 'ControlError';
    this.code = code;
    this.details = details;
  }
}

function assertControl(condition, code, message, details = null) {
  if (!condition) throw new ControlError(code, message, details);
}

module.exports = { ControlError, assertControl };
