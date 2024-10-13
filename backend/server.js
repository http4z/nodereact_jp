const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// Configuración de la base de datos PostgreSQL
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'bd_nodereact_jp',  
    password: 'admin', 
    port: 5432,
});

const JWT_SECRET = 'mi_clave_secreta_super_segura';  // Clave secreta para firmar los tokens JWT

pool.connect((err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
    } else {
        console.log('Conexión a PostgreSQL exitosa');
    }
});

app.use(cors());
app.use(bodyParser.json());

// Rutas de la API
app.get('/api/estudiantes', async (req, res) => {
    const result = await pool.query('SELECT * FROM estudiantes');
    res.json(result.rows);
});

app.post('/api/estudiantes', async (req, res) => {
    const { nombre } = req.body;
    const result = await pool.query('INSERT INTO estudiantes (nombre) VALUES ($1) RETURNING *', [nombre]);
    res.json(result.rows[0]);
});

app.put('/api/estudiantes/:id', async (req, res) => {
    const { id } = req.params;
    const { nombre } = req.body;
    const result = await pool.query('UPDATE estudiantes SET nombre = $1 WHERE id = $2 RETURNING *', [nombre, id]);
    res.json(result.rows[0]);
});

app.delete('/api/estudiantes/:id', async (req, res) => {
    const { id } = req.params;
    await pool.query('DELETE FROM estudiantes WHERE id = $1', [id]);
    res.sendStatus(204);
});

// Ruta de registro de usuarios
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // Cifrar la contraseña

    try {
        const result = await pool.query(
            'INSERT INTO usuarios (username, password) VALUES ($1, $2) RETURNING *',
            [username, hashedPassword]
        );
        res.status(201).json({ message: 'Usuario registrado exitosamente', user: result.rows[0] });
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(400).json({ error: 'Error al registrar usuario' });
    }
});

// Ruta de inicio de sesión
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ error: 'Usuario no encontrado' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);  // Verificar la contraseña
        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Contraseña incorrecta' });
        }

        // Generar el token JWT
        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(500).json({ error: 'Error en el servidor' });
    }
});

// Middleware para verificar token JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'Token requerido' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Token inválido' });
        req.userId = decoded.id;
        next();
    });
};

// Ruta protegida
app.get('/api/protected', verifyToken, (req, res) => {
    res.json({ message: 'Acceso a ruta protegida' });
});



app.listen(port, () => {
    console.log(`Servidor escuchando en http://localhost:${port}`);
});
