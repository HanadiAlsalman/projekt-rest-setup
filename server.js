import express from 'express';
import mysql from 'mysql2/promise';
import dbCredentials from './db-credentials.js';
import session from "express-session"
import crypto from "crypto"

const app = express();
const port = 3000;

app.use(express.json());

app.use(session({
  secret: 'min-hemlighet', // en hemlig nyckel för att signera session-cookie
  resave: false, // undviker att spara sessionen om den inte ändras
  saveUninitialized: true, // spara en ny session som inte har blivit initialiserad
  cookie: {secure: false} // cookie-inställningar, secure bör vara true i produktion med HTTPS
}))


// Skapa anslutningen direkt vid start
const db = await mysql.createConnection(dbCredentials);

// Testa med en enkel GET-endpoint
app.get("/", async (req, res) => {
  res.json({ message: "Servern är igång" });
});

// Hashfunktion
function hash(word) {
  const salt = "mitt-salt"
  return crypto.pbkdf2Sync(word, salt, 1000, 64, "sha512").toString("hex")
}

app.get('/check-session', (req, res) => {
  if (req.session.page_views){
    req.session.page_views++;
    res.send(`Du har besökt denna sida ${req.session.page_views} gånger`);
  } else {
    req.session.page_views = 1;
    res.send('Välkommen till denna sida för första gången!');
  }
})


// 1. Registrera ny användare
app.post("/api/users/register", async (req, res) => {
  const { username, email, password } = req.body
  if (!username || !email || !password) {
    return res.status(400).json({ message: "Fyll i alla fält." })
  }

  try {
    const [result] = await db.execute(`
      INSERT INTO users (username, email, password_hash, role, created_at, updated_at)
      VALUES (?, ?, ?, 'user', NOW(), NOW())
    `, [username, email, hash(password)])

    return res.status(201).json({ message: "Användare skapad", userId: result.insertId })
  } catch (err) {
    console.log(err)
    return res.status(500).json({ message: "Fel vid registrering" })
  }
})


// 2. Logga in
app.post("/api/users/login", async (req, res) => {
  if (req.session.user) {
    return res.status(400).json({ message: "Redan inloggad." })
  }

  const { username, password } = req.body
  try {
    const [result] = await db.execute(`
      SELECT * FROM users WHERE username = ?
    `, [username])

    const user = result[0]
    if (!user || user.password_hash !== hash(password)) {
      return res.status(401).json({ message: "Felaktigt användarnamn eller lösenord." })
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role
    }

    return res.status(200).json({ message: `Välkommen ${user.username}` })
  } catch (err) {
    console.log(err)
    return res.status(500).json({ message: "Fel vid inloggning" })
  }
})


// 3. Logga ut
app.delete("/api/users/logout", (req, res) => {
  if (!req.session.user) {
    return res.status(400).json({ message: "Ingen är inloggad." })
  }

  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ message: "Fel vid utloggning." })
    }

    return res.json({ message: "Du är utloggad." })
  })
})

// 4. Hämta inloggad användares profil
app.get("/api/users/profil", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Du är inte inloggad." })
  }

  const userId = req.session.user.id
  try {
    const [result] = await db.execute(`
      SELECT id, username, email, role, created_at, updated_at
      FROM users WHERE id = ?
    `, [userId])

    return res.json(result[0])
  } catch (err) {
    console.log(err)
    return res.status(500).json({ message: "Fel vid hämtning av profil." })
  }
})


//5. Lista alla användare
app.get("/api/users", async (req, res) => {
  // Kontrollera om användaren är inloggad
  if (!req.session.user) {
    return res.status(401).json({ message: "Du är inte inloggad." });
  }

  // Kontrollera om användaren är admin
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ message: "Du har inte behörighet att se alla användare." });
  }

  try {
    const [result] = await db.execute(`
      SELECT id, username, email, role, created_at, updated_at FROM users
    `);
    return res.json(result);
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Fel vid hämtning av användare." });
  }
})

// Forums
//1. Skapa forum (kräver inloggning)
app.post("/api/forums/create", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Måste vara inloggad" });
  }

  const { name, description } = req.body;
  const creatorId = req.session.user.id;

  try {
    const [result] = await db.execute(
      `INSERT INTO forums (name, description, creator_id, created_at, updated_at)
       VALUES (?, ?, ?, NOW(), NOW())`,
      [name, description || null, creatorId]
    );
    return res.status(201).json({ message: "Forum skapat!", forumId: result.insertId });
  } catch (e) {
    console.log(e);
    return res.status(500).json({ message: "Fel vid forumskapande" });
  }
});

//2. alla kan se forum, ingen inloggning krävs
app.get("/api/forums", async (req, res) => {
  try {
    const [forums] = await db.execute(`
      SELECT f.id, f.name, f.description, f.created_at, u.username AS created_by
      FROM forums f
      JOIN users u ON f.creator_id = u.id
      ORDER BY f.created_at DESC
    `);

    const formatted = forums.map(f => ({
      id: f.id,
      name: f.name,
      description: f.description,
      created_by: f.created_by,
      created_at: f.created_at
    }));

    return res.status(200).json(formatted);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Fel vid hämtning av forum." });
  }
});

//3. Hämtar forum baserat på namn
app.get("/api/forums/search", async (req, res) => {
  const query = req.query.query;

  if (!query) {
    return res.status(400).json({ message: "Sökord saknas." });
  }

  try {
    const [results] = await db.execute(`
      SELECT f.id, f.name, f.description, f.created_at, u.username AS created_by
      FROM forums f
      JOIN users u ON f.creator_id = u.id
      WHERE f.name LIKE ? OR f.description LIKE ?
      ORDER BY f.created_at DESC
    `, [`%${query}%`, `%${query}%`]);

    if (results.length === 0) {
      return res.status(404).json({ message: "Inga forum hittades." });
    }

    const formatted = results.map(f => ({
      id: f.id,
      name: f.name,
      description: f.description,
      created_by: f.created_by,
      created_at: f.created_at
    }));

    return res.status(200).json(formatted);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Fel vid sökning." });
  }
});


// Threads
//1. Skapa threads, kräver inloggning
app.post("/api/threads/create", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Du måste vara inloggad för att skapa en tråd." });
  }

  const { title, description, forum, visibility } = req.body;
if (!title || !forum) {
  return res.status(400).json({ message: "Titel och forum krävs." });
}

const vis = visibility === "private" ? "private" : "public";

const [fres] = await db.execute(
  `SELECT id FROM forums WHERE name = ?`,
  [forum]
);
if (!fres.length) {
  return res.status(404).json({ message: `Forum '${forum}' finns inte.` });
}
const forumId = fres[0].id;
const ownerId = req.session.user.id;

  try {
    const [result] = await db.execute(
  `INSERT INTO threads (forum_id, title, description, visibility, owner_id, created_at, updated_at)
   VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
  [forumId, title, description || null, vis, ownerId]
);

    console.log("Skickade värden:", { title, description, forum, visibility });

    return res.status(201).json({
      message: "Tråd skapad.",
      threadId: result.insertId
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Fel vid skapande av tråd." });
  }
});

//2. hämta alla public trådar, ingen inloggning krävs
app.get("/api/threads", async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT t.id, t.title, t.created_at AS created, u.username AS owner, f.name AS forum
      FROM threads t
      JOIN users u ON u.id = t.owner_id
      JOIN forums f ON f.id = t.forum_id
      WHERE t.visibility = 'public'
      ORDER BY t.created_at DESC
    `);
    return res.json(results);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Fel vid hämtning trådar." });
  }
});





app.listen(port, () => {
  console.log(`Servern körs på http://localhost:${port}`);
});
