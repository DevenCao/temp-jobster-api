const testUser = require('../middleware/test-user')
const authenticateUser = require('../middleware/authentication')
const rateLimit = require('express-rate-limit')
const router = require('express').Router();
const { register, login, updateUser, } = require('../controllers/auth');


const apiLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 1, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
	message: {
        msg: 'Too many requests from this IP, please try again in 15 minutes.'
    }
})

router.post('/register', apiLimiter, register);
router.post('/login', apiLimiter, login);
router.patch('/updateUser', authenticateUser, testUser, updateUser)

module.exports = router
