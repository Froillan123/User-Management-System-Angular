module.exports = errorHandler;

function errorHandler(err, req, res, next) {
    console.error('Error encountered:', err);
    
    switch (true) {
        case typeof err === 'string':
            // custom application error
            const is404 = err.toLowerCase().endsWith('not found');
            const isEmailError = err.toLowerCase().includes('email') && err.toLowerCase().includes('already registered');
            const statusCode = is404 ? 404 : (isEmailError ? 409 : 400);
            return res.status(statusCode).json({ message: err });
        case err.name === 'UnauthorizedError':
            // jwt authentication error
            return res.status(401).json({ message: 'Unauthorized' });
        case err.name === 'SequelizeUniqueConstraintError':
            // Database unique constraint error (like duplicate email)
            return res.status(409).json({ message: 'A record with the same details already exists' });
        default:
            return res.status(500).json({ message: err.message });
    }
}