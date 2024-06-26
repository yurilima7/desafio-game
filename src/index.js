const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3010;

app.use(bodyParser.json());                 
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

mongoose.connect('mongodb+srv://luizcgjunior2018:cU70mFa0ROEQfrOB@cluster0.jgo39xq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('Error connecting to MongoDB:', err));

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

UserSchema.pre('save', async function (next) {
    const user = this;
    if (!user.isModified('password')) return next();

    try {
        const hashedPassword = await bcrypt.hash(user.password, 10);
        user.password = hashedPassword;
        next();
    } catch (err) {
        return next(err);
    }
});

const User = mongoose.model('User', UserSchema);


const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'luiz_senha_jwt', 
};

passport.use(new JwtStrategy(jwtOptions, async (jwt_payload, done) => {
    try {
        const user = await User.findById(jwt_payload.sub);
        if (user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    } catch (err) {
        return done(err, false);
    }
}));

// Rota para cadastrar um novo usuário
app.post('/api/users', validateUserData, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { name, email, password } = req.body;
        const newUser = new User({ name, email, password });
        const savedUser = await newUser.save();
        res.status(201).json(savedUser);
    } catch (err) {
        res.status(400).send(err);
    }
});

// Rota para login e geração de token JWT
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            const token = jwt.sign({ sub: user._id }, 'seu_secreto_jwt', { expiresIn: '1h' });
            res.json({ token });
        } else {
            res.status(401).json({ message: 'Credenciais inválidas.' });
        }
    } catch (err) {
        res.status(500).json({ message: 'Erro interno no servidor.' });
    }
});

// validação para dados do usuário
function validateUserData(req, res, next) {
    body('name').trim().isLength({ min: 1 }).escape().withMessage('Nome é obrigatório.');
    body('email').isEmail().normalizeEmail().withMessage('Email inválido.');
    body('password').isLength({ min: 6 }).withMessage('A senha deve ter pelo menos 6 caracteres.');

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    next();
}

// Iniciar o servidor Express
app.listen(port, () => {
    console.log(`App running on port ${port}`);
});
