'use strict'

const bcrypt = require('bcryptjs');

                                            // Fonction pour vérifier le mot de passe
const verifyPassword = async (inputPassword, storedPassword) => {
  return bcrypt.compare(inputPassword, storedPassword);
};
const fastify = require('fastify')();

fastify.post('/login', async (request, reply) => {
  const { username, password } = request.body;

                                            // Vérification de l'utilisateur dans la base de données (c'est un exemple, il faut connecter une vraie BDD)
  const user = await getUserByUsername(username);  // getUserByUsername est une fonction qui récupère l'utilisateur par son nom d'utilisateur

  if (!user) {
    return reply.status(400).send({ message: 'Utilisateur non trouvé' });
  }

                                            // Vérification du mot de passe
  const isPasswordValid = await verifyPassword(password, user.password);
  if (!isPasswordValid) {
    return reply.status(400).send({ message: 'Mot de passe incorrect' });
  }

 // Création du JWT
  const token = createToken(user.id);

 // Envoi de la réponse avec le token
  return reply.send({ message: 'Connexion réussie', token });
});

                                            // Exemple de fonction pour récupérer l'utilisateur depuis une base de données (ici un objet fictif).
const getUserByUsername = async (username) => {
  // Cette fonction devrait interroger ta base de données
  const users = [
    { id: 1, username: 'john', password: '$2a$10$JbtxR3vQFHZH0Qz.cTcmB.kh7twpIVjlTj.bml6ChflU7VfW8RUFO' }, // mot de passe haché
    // d'autres utilisateurs...
  ];
  return users.find(user => user.username === username);
};

fastify.decorate("authenticate", async (request, reply) => {
  try {
    const token = request.headers['authorization']?.split(' ')[1];  // Récupérer le token du header Authorization

    if (!token) {
      return reply.status(401).send({ message: 'Token manquant' });
    }

    const decoded = jwt.verify(token, 'tonSecretDeClé'); // Vérifier le token
    request.user = decoded; // Stocker les informations de l'utilisateur dans la requête
  } catch (err) {
    return reply.status(401).send({ message: 'Token invalide ou expiré' });
  }
});

                                        // Exemple d'une route protégée
fastify.get('/protected', { preHandler: fastify.authenticate }, async (request, reply) => {
  return { message: 'Accès autorisé', user: request.user };
});
