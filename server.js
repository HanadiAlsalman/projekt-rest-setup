import express from 'express';
import mysql from 'mysql2/promise';
import dbCredentials from './db-credentials.js';

const app = express();
const port = 3000;

app.use(express.json());

// Skapa anslutningen direkt vid start
const db = await mysql.createConnection(dbCredentials);

// Testa med en enkel GET-endpoint
app.get("/", async (req, res) => {
  res.json({ message: "Servern är igång" });
});

app.listen(port, () => {
  console.log(`Servern körs på http://localhost:${port}`);
});
