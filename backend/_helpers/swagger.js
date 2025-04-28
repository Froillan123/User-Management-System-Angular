const express = require('express');
const router = express.Router();
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('./swagger.yaml');

// This pattern can cause issues with path-to-regexp
// router.use('/', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Use explicit routes instead
router.get('/', swaggerUi.setup(swaggerDocument));
router.use(swaggerUi.serve);

module.exports = router;