'use strict';

/*
 * Dependency-free evaluator for the exact Draft 2020-12 vocabulary used by
 * controller-owned machine contracts. Unknown assertion keywords fail closed,
 * so tests execute checked-in schemas instead of only inspecting their shape.
 */

const ANNOTATIONS = new Set([
  '$schema',
  '$id',
  'title',
  'description',
  '$comment',
]);
const CONTAINERS = new Set(['$defs', 'properties']);
const ASSERTIONS = new Set([
  '$ref',
  'type',
  'const',
  'enum',
  'required',
  'additionalProperties',
  'minLength',
  'maxLength',
  'pattern',
  'minimum',
  'maximum',
  'allOf',
  'oneOf',
  'not',
]);

function schemaPointer(root, reference) {
  if (!reference.startsWith('#/')) {
    throw new Error(`unsupported non-local schema reference: ${reference}`);
  }
  return reference.slice(2).split('/').reduce((value, segment) => {
    const key = segment.replace(/~1/g, '/').replace(/~0/g, '~');
    if (!value || !Object.prototype.hasOwnProperty.call(value, key)) {
      throw new Error(`unresolved schema reference: ${reference}`);
    }
    return value[key];
  }, root);
}

function jsonTypeMatches(value, expected) {
  if (expected === 'null') return value === null;
  if (expected === 'array') return Array.isArray(value);
  if (expected === 'object') {
    return value !== null
      && typeof value === 'object'
      && !Array.isArray(value);
  }
  if (expected === 'integer') {
    return typeof value === 'number' && Number.isInteger(value);
  }
  return typeof value === expected;
}

function deepEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function assertKnownVocabulary(schema, location = '#') {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    throw new Error(`schema ${location} must be an object`);
  }
  for (const key of Object.keys(schema)) {
    if (
      !ANNOTATIONS.has(key)
        && !CONTAINERS.has(key)
        && !ASSERTIONS.has(key)
    ) {
      throw new Error(`unsupported schema keyword ${location}/${key}`);
    }
  }
  for (const container of CONTAINERS) {
    for (const [key, child] of Object.entries(schema[container] || {})) {
      assertKnownVocabulary(child, `${location}/${container}/${key}`);
    }
  }
  for (const keyword of ['allOf', 'oneOf']) {
    (schema[keyword] || []).forEach((child, index) => {
      assertKnownVocabulary(child, `${location}/${keyword}/${index}`);
    });
  }
  if (schema.not) assertKnownVocabulary(schema.not, `${location}/not`);
}

function validateNode(root, schema, value) {
  if (schema.$ref) {
    return validateNode(root, schemaPointer(root, schema.$ref), value);
  }
  const expectedTypes = Array.isArray(schema.type)
    ? schema.type
    : schema.type
      ? [schema.type]
      : null;
  if (
    expectedTypes
      && !expectedTypes.some((expected) => (
        jsonTypeMatches(value, expected)
      ))
  ) {
    return false;
  }
  if (
    Object.prototype.hasOwnProperty.call(schema, 'const')
      && !deepEqual(value, schema.const)
  ) {
    return false;
  }
  if (schema.enum && !schema.enum.some((item) => deepEqual(item, value))) {
    return false;
  }
  if (typeof value === 'string') {
    if (
      schema.minLength !== undefined
        && [...value].length < schema.minLength
    ) {
      return false;
    }
    if (
      schema.maxLength !== undefined
        && [...value].length > schema.maxLength
    ) {
      return false;
    }
    if (schema.pattern && !(new RegExp(schema.pattern, 'u')).test(value)) {
      return false;
    }
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) return false;
    if (schema.maximum !== undefined && value > schema.maximum) return false;
  }
  if (
    value !== null
      && typeof value === 'object'
      && !Array.isArray(value)
  ) {
    for (const required of schema.required || []) {
      if (!Object.prototype.hasOwnProperty.call(value, required)) return false;
    }
    const properties = schema.properties || {};
    if (
      schema.additionalProperties === false
        && Object.keys(value).some((key) => (
          !Object.prototype.hasOwnProperty.call(properties, key)
        ))
    ) {
      return false;
    }
    for (const [key, child] of Object.entries(properties)) {
      if (
        Object.prototype.hasOwnProperty.call(value, key)
          && !validateNode(root, child, value[key])
      ) {
        return false;
      }
    }
  }
  if (
    schema.allOf
      && !schema.allOf.every((child) => validateNode(root, child, value))
  ) {
    return false;
  }
  if (
    schema.oneOf
      && schema.oneOf.filter((child) => validateNode(root, child, value))
        .length !== 1
  ) {
    return false;
  }
  if (schema.not && validateNode(root, schema.not, value)) return false;
  return true;
}

function compileDraft202012(schema) {
  if (
    schema.$schema
      !== 'https://json-schema.org/draft/2020-12/schema'
  ) {
    throw new Error('schema must declare Draft 2020-12');
  }
  assertKnownVocabulary(schema);
  return (value) => validateNode(schema, schema, value);
}

module.exports = {
  compileDraft202012,
};
