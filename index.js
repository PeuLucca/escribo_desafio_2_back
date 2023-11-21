const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port = 5000;
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(cors());
app.use(bodyParser.json());

const secretKey = "37061ea2f604acd2a99fd888c1b076799e6991e90173a838044a728b2bc99be1";

// Conexão com banco de dados
const db = mysql.createConnection({
  host: "roundhouse.proxy.rlwy.net",
  port: "38472",
  user: "root",
  password: "4c3D52eCAG1D2dF2dcdDAaeFABFBH2f-",
  database: "railway",
});

db.connect((err) => {
  if (err) {
    console.error('Erro ao conectar ao MySQL:', err.stack);
    return;
  }
  console.log('Conectado ao banco de dados MySQL');
});

// Servidor rodando
app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});

// Token
const generateJwtToken = (email) => {
    return jwt.sign({ email }, secretKey, { expiresIn: '30m' });
}

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ mensagem: 'Não autorizado' });
    }

    jwt.verify(token.replace('Bearer ', ''), secretKey, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ mensagem: 'Token expirado' });
            } else {
                return res.status(403).json({ mensagem: 'Não autorizado' });
            }
        }
        req.user = user;
        next();
    });
};


// Sign Up (Criação de Cadastro):
app.post('/signup', async (req, res) => {
  const { nome, email, senha, telefone } = req.body;
  const { numero, ddd } = telefone;
  const hash = await bcrypt.hash(senha, 10);

  db.query('SELECT * FROM usuario WHERE email = ?', [email], (error, results) => {
    if (error) {
      return res.status(500).json({ mensagem: 'Erro interno no servidor' });
    }

    if (results.length > 0) {
      return res.status(400).json({ mensagem: 'E-mail já existente' });
    }

    const dataCriacao = new Date();
    const dataAtualizacao = new Date();
    const ultimoLogin = new Date();
    const token = generateJwtToken(email);

    db.query(
      'INSERT INTO usuario (nome, email, senha, ddd, telefone, data_criacao, data_atualizacao, ultimo_login, token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [nome, email, hash, ddd, numero, dataCriacao, dataAtualizacao, ultimoLogin, token],
      (error, result) => {
        if (error) {
          return res.status(500).json({ mensagem: "Erro ao cadastrar usuário" });
        }

        return res.json({
          id: result.insertId,
          data_criacao: dataCriacao,
          data_atualizacao: dataAtualizacao,
          ultimo_login: ultimoLogin,
          token: token,
        });
      }
    );
  });
});

// Sign In (Autenticação):
app.post('/signin', (req, res) => {
    const { email, senha } = req.body;
  
    db.query('SELECT * FROM usuario WHERE email = ?', [email], (error, results) => {
      if (error) {
        console.error('Erro ao consultar o banco de dados:', error);
        return res.status(500).json({ mensagem: 'Erro interno do servidor' });
      }
    
      if (results.length === 0) {
        return res.status(401).json({ mensagem: 'Usuário e/ou senha inválidos' });
      }
  
      const usuario = results[0];
      bcrypt.compare(senha, usuario.senha, async (bcryptError, match) => {
        if (bcryptError) {
          console.error('Erro ao comparar as senhas:', bcryptError);
          return res.status(500).json({ mensagem: 'Erro interno do servidor' });
        }
    
        if (!match) {
          return res.status(401).json({ mensagem: 'Usuário e/ou senha inválidos' });
        }
  
        const token = generateJwtToken(email);
        const now = new Date();

        db.query('UPDATE usuario SET token = ?, ultimo_login = ? WHERE id = ?', [token, now, usuario.id], (updateError) => {
          if (updateError) {
            console.error('Erro ao atualizar o token e a última data de login:', updateError);
            return res.status(500).json({ mensagem: 'Erro interno do servidor' });
          }
  
          res.json({
            id: usuario.id,
            data_criacao: usuario.data_criacao,
            data_atualizacao: usuario.data_atualizacao,
            ultimo_login: now,
            token: token,
          });
        });
      });
    });
  });
  
// Buscar Usuário
app.get('/getuser', authenticateToken, (req, res) => {
  const userEmail = req.user.email;

  db.query('SELECT * FROM usuario WHERE email = ?', [userEmail], (error, results) => {
    if (error) {
      console.error('Erro ao consultar o banco de dados:', error);
      return res.status(500).json({ mensagem: 'Erro interno do servidor' });
    }
  
    if (results.length === 0) {
      return res.status(404).json({ mensagem: 'Usuário não encontrado' });
    }
  
    const usuario = results[0];
    res.json(usuario);
  });
});
