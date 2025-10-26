const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/auth.controller');
const authMiddleware = require('../middlewares/auth.middleware')

router.post('/signup', ctrl.signup);
router.post('/login', ctrl.login);
router.post('/refresh', ctrl.refresh);
router.post('/logout', ctrl.logout);
router.post('/request-password-reset', ctrl.requestPasswordResetController);
router.post('/reset-password', ctrl.resetPasswordController);
router.post('/change-password', authMiddleware, ctrl.changePasswordController);

module.exports = router;
