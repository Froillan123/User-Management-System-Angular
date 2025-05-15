const express = require('express');
const router = express.Router();
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('./swagger.yaml');

// The issue is with path-to-regexp parsing URLs in the swagger document
// Use a more explicit approach without relying on path matching
router.use('', swaggerUi.serve);
router.get('', swaggerUi.setup(swaggerDocument));

module.exports = router;