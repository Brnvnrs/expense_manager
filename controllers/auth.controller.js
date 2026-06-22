const bcrypt = require('bcrypt');
const pool = require('../db');

async function register(req, res) {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            error: { code: 'MISSING_FIELDS', message: 'name, email y password son obligatorios' }
        });
    }

    if (password.length < 6) {
        return res.status(400).json({
            error: { code: 'WEAK_PASSWORD', message: 'La contraseña debe tener al menos 6 caracteres' }
        });
    }

    try {
        const email_already_exists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (email_already_exists.rows.length > 0) {
            return res.status(409).json({
                error: { code: 'EMAIL_TAKEN', message: 'Ese email ya está registrado' }
            });
        }

        const hash = await bcrypt.hash(password, 10);

        const result = await pool.query(
            `INSERT INTO users (name, email, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id, name, email, created_at`,
            [name, email, hash]
        );
        return res.status(201).json({ user: result.rows[0] });
    } catch (err) {
        console.error(err);
        return res.status(500).json({
            error: { code: 'INTERNAL_ERROR', message: 'we had a problem while we were creating the user ' }
        });

    }



}
module.exports = { register }