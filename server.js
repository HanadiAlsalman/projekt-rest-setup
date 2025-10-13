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
//1. Skapa threads (lägg in user som moderator direkt), kräver inloggning
app.post("/api/threads/create", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Du måste vara inloggad för att skapa en tråd." });
  }

  const { title, description, forum, visibility } = req.body;
  if (!title || !forum) {
  return res.status(400).json({ message: "Titel och forum krävs." });
}

const vis = visibility === "private" ? "private" : "public";

//kontrollera att forumet finns
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
   const threadId = result.insertId;

    // Lägg till skaparen som master moderator i thread_moderators tabellen
    await db.execute(
      `INSERT INTO thread_moderators (thread_id, user_id, role) 
       VALUES (?, ?, 'master')`,
      [threadId, ownerId]
    );

    return res.status(201).json({
      message: "Tråd skapad och du har utsetts till master moderator.",
      threadId: threadId
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

//3. hämtar tråd efter id där accesskontroll sker på privata trådar.
app.get("/api/threads/:id", async (req, res) => {
  const threadId = req.params.id;
  const user = req.session.user;

  const [threads] = await db.execute(`
    SELECT * FROM threads WHERE id = ?
  `, [threadId]);

  const thread = threads[0];
  if (!thread) return res.status(404).json({ message: "Tråden finns inte." });

  // ACL: kontrollera Privata trådar får bara visas för trådskapare & inbjudna moderatorer
  if (thread.visibility === 'private') {
    if (!user) return res.status(403).json({ message: "Privat tråd, du är inte inloggad." });

    // Är user ägare eller moderator
    const [mods] = await db.execute(`
      SELECT * FROM thread_moderators WHERE user_id = ? AND thread_id = ?
    `, [user.id, threadId]);

    if (user.id !== thread.owner_id && mods.length === 0) {
      return res.status(403).json({ message: "Privat tråd. Du har inte access." });
    }
  }

  return res.json(thread);
});


// 4. Trådägare kan bjuda in andra users till sin tråd
app.post("/api/threads/:id/moderators", async (req, res) => {
  const threadId = req.params.id;
  const { userId: userIdToInvite } = req.body;
  const threadUser = req.session.user;

  // Kontrollera inloggning
  if (!threadUser) {
    return res.status(401).json({ message: "Du måste vara inloggad." });
  }

  // Förhindra att man bjuder in sig själv
  if (String(userIdToInvite) === String(threadUser.id)) {
    return res.status(400).json({ message: "Du kan inte bjuda in dig själv." });
  }

  try {
    // Kontrollera att användaren är master moderator i tråden
    const [mods] = await db.execute(
      `SELECT role FROM thread_moderators WHERE user_id = ? AND thread_id = ?`,
      [threadUser.id, threadId]
    );

    if (mods.length === 0) {
      return res.status(403).json({ message: "Du är inte moderator för denna tråd." });
    }

    const isMasterModerator = mods[0].role === "master";

    if (!isMasterModerator) {
      return res.status(403).json({ message: "Endast huvudansvarig mastermoderator kan bjuda in nya moderatorer." });
    }

    // Lägg till den nya användaren som ASSISTANT moderator
    await db.execute(
      `INSERT INTO thread_moderators (user_id, thread_id, role, assigned_at)
       VALUES (?, ?, 'helper', NOW())`,
      [userIdToInvite, threadId]
    );

    return res.json({ message: "Helpmoderator har utsett till thread " });

  } catch (err) {
    // Hantera om användaren redan är moderator
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ message: "Användaren är redan moderator för denna tråd." });
    }
    console.error(err);
    return res.status(500).json({ message: "Fel vid tillägg av moderator." });
  }
});

// 5. Ta bort som soft delete en moderator från en tråd
app.delete("/api/threads/:id/moderators/:userId", async (req, res) => {
  const threadId = req.params.id;
  const userIdToRemove = req.params.userId;
  const threadUser = req.session.user;

  // ACL: Kontrollera att användaren är inloggad
  if (!threadUser) {
    return res.status(401).json({ message: "Du måste vara inloggad." });
  }

  try {
    // Kontrollera att användaren är moderator i tråden
    const [mods] = await db.execute(
      `SELECT role FROM thread_moderators WHERE user_id = ? AND thread_id = ?`,
      [threadUser.id, threadId]
    );

    if (mods.length === 0) {
      return res.status(403).json({ message: "Du är inte moderator för denna tråd." });
    }

    const isMasterModerator = mods[0].role === "master";

    // Endast master får ta bort andra moderatorer
    if (!isMasterModerator) {
      return res.status(403).json({ message: "Endast huvudansvarig masterModerator kan ta bort moderatorer." });
    }

    // Förhindra att master tar bort sig själv
    if (String(threadUser.id) === String(userIdToRemove)) {
      return res.status(400).json({ message: "Du kan inte ta bort dig själv som huvudmoderator." });
    }

    // Kontrollera att den andra användaren verkligen är aktiv moderator
    const [targetMods] = await db.execute(
      `SELECT * FROM thread_moderators WHERE user_id = ? AND thread_id = ? AND is_active = 1`,
      [userIdToRemove, threadId]
    );

    if (targetMods.length === 0) {
      return res.status(404).json({ message: "Användaren är inte aktiv moderator i denna tråd." });
    }

    // Soft delete: sätt is_active = 0
    await db.execute(
      `UPDATE thread_moderators 
       SET is_active = 0
       WHERE user_id = ? AND thread_id = ?`,
      [userIdToRemove, threadId]
    );

    return res.json({ message: "Moderator har inaktiverats (soft delete)." });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Fel vid borttagning av moderator." });
  }
});







app.listen(port, () => {
  console.log(`Servern körs på http://localhost:${port}`);
});
