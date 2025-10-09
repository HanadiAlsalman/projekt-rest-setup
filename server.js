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

// Kontrollera om user är 18 år
function isOver18(birthDateString) {
    const today = new Date();
    const birthDate = new Date(birthDateString);
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDifference = today.getMonth() - birthDate.getMonth();

    if (monthDifference < 0 || (monthDifference === 0 && today.getDate() < birthDate.getDate())) {
        age--;
    }
    return age >= 18;
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
// ACL: det kräver birth_date och validerar ålder 18
app.post("/api/users/register", async (req, res) => {
  const { username, email, password, birth_date } = req.body
  if (!username || !email || !password || !birth_date) {
    return res.status(400).json({ message: "Fyll i alla fält & födelsedatum YYYY-MM-DD" })
  }

  // Ålderskontroll
  if(!isOver18(birth_date)) {
    return res.status(403).json({message: "Du måste vara minst 18 år för att skapa ett konto"})
  }

  try {
    const [result] = await db.execute(`
      INSERT INTO users (username, email, password_hash, role, birth_date, created_at, updated_at)
      VALUES (?, ?, ?, 'user', ?, NOW(), NOW())
    `, [username, email, hash(password), birth_date])

    return res.status(201).json({ message: "Användare skapad", userId: result.insertId })
  } catch (err) {
    console.log(err)
    return res.status(500).json({ message: "Fel vid registrering" })
  }
})


// 2. Logga in
app.post("/api/users/login", async (req, res) => {
// ACL: förhindra inloggade igen om user är redan inloggad
  if (req.session.user) {
    return res.status(400).json({ message: "Redan inloggad. Logga ut först" })
  }

  const { username, password } = req.body
  // kontrollera att alla fält är ifyllda
  if (!username || !password) {
      return res.status(400).json({ message: "Användarnamn och lösenord krävs." });
  }
  try {
    // försök hitta användaren i db baserade på usernamn
    const [result] = await db.execute(`
      SELECT * FROM users WHERE username = ?
    `, [username])

    const user = result[0]
    // kontrollera om user existerar och om lösenordet matchar
    if (!user || user.password_hash !== hash(password)) {
      return res.status(401).json({ message: "Felaktigt användarnamn eller lösenord." })
    }

    // ACL: Kontrollera om kontot är aktivt
        if (user.is_active === 0 || user.is_active === false) {
            return res.status(401).json({ message: "Kontot är inaktiverat. Kontakta support." })
        }

    // om user kunde logga in, byttas roller från anonymous till inloggad user

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
  //ACL: kontrollera att user måste vara inloggad (user, moderator, admin)
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
  //ACL: kontrollera att user måste vara inloggad (user, moderator, admin)
  if (!req.session.user) {
    return res.status(401).json({ message: "Du är inte inloggad. Kräver roll: user/moderator/admin" })
  }

  const userId = req.session.user.id
  try {
    const [result] = await db.execute(`
      SELECT id, username, email, role, birth_date, created_at, updated_at
      FROM users WHERE id = ?
    `, [userId])

    return res.json(result[0])
  } catch (err) {
    console.log(err)
    return res.status(500).json({ message: "Fel vid hämtning av profil." })
  }
})

// 5. Uppdatera egen profil (Email & Lösenord)
app.put("/api/users/profil", async (req, res) => {

    // ACL: Måste vara inloggad (user, moderator eller admin)
    if (!req.session.user) {
        return res.status(401).json({ message: "Du måste vara inloggad" });
    }

    const { email, password } = req.body;
    const userId = req.session.user.id;
    let sqlUpdates = [];
    let sqlValues = [];

    // Kontrollera om minst ett av fälten (email eller password) skickades
    if (!email && !password) {
        return res.status(400).json({ message: "Du kan uppdatera profil men inte usernamn" });
    }

    // uppdatering av lösenord
    if (password) {
        // Det använder hash-funktionen för att säkra det nya lösenordet
        const newPasswordHash = hash(password);
        sqlUpdates.push("password_hash = ?");
        sqlValues.push(newPasswordHash);
    }

    // uppdatering av e-post
    if (email) {
        sqlUpdates.push("email = ?");
        sqlValues.push(email);
    }

    // Lägg till uppdatering av 'updated_at'
    sqlUpdates.push("updated_at = NOW()");
    sqlValues.push(userId); // lägg till userid till sist i sqlvalues för att match med "where id=?"

    //sql query
    const sqlQuery = `
        UPDATE users
        SET ${sqlUpdates.join(", ")}
        WHERE id = ?
    `;

    try {
        const [result] = await db.execute(sqlQuery, sqlValues);

        if (result.affectedRows === 0) {
            //Konrollera att alla rader uppdaterades
            return res.status(404).json({ message: "Kunde inte hitta eller uppdatera användaren. Kontrollera att ditt konto existerar." });
        }

        return res.status(200).json({ message: "Profil uppdaterad framgångsrikt." });

    } catch (err) {
        console.error(err);
        // Konrtollera om den nya e-posten redan används
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: "Den angivna e-postadressen används redan av ett annat konto." });
        }
        return res.status(500).json({ message: "Fel vid uppdatering av profilen." });
    }
});

//6. Lista alla användare
app.get("/api/users", async (req, res) => {
  // Kontrollera om användaren är inloggad
  if (!req.session.user) {
    return res.status(401).json({ message: "Åtkomst nekad, Du är inte inloggad." });
  }

  // Kontrollera om användaren är admin
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ message: "Du har inte behörighet att se alla användare." });
  }

  try {
    const [result] = await db.execute(`
      SELECT id, username, email, role, birth_date, created_at, updated_at, is_active FROM users
    `);
    return res.json(result);
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Fel vid hämtning av användare." });
  }
})

// 7. Frys/aktivera userskonto, admins roll
// ACL: admins roll
app.put("/api/admin/users/freeze/:id", async (req, res) => {

    // ACL: måste vara inloggad
    if (!req.session.user) {
        return res.status(401).json({ message: "Åtkomst nekad. Du är inte inloggad." });
    }

    // ACL: måste vara admin
    if (req.session.user.role !== "admin") {
        return res.status(403).json({ message: `Åtkomst nekad. Din roll (${req.session.user.role}) är inte tillräcklig, det kräver roll: admin` });
    }

    const userIdToFreeze = req.params.id;
    const { is_active } = req.body;

    // Validera inmatning
    if (typeof is_active !== 'boolean') {
         return res.status(400).json({ message: "Status måste vara true (aktiv) eller false (frys)." });
    }

    // ACL: Förhindra att admin fryser sitt eget konto
    if (String(userIdToFreeze) === String(req.session.user.id)) {
        return res.status(400).json({ message: "Du kan inte ändra statusen på ditt eget administratörskonto." });
    }

    try {
        // Uppdatera 'is_active' fält
        const [result] = await db.execute(
            `UPDATE users SET is_active = ?, updated_at = NOW() WHERE id = ?`,
            [is_active, userIdToFreeze]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: `User med ID ${userIdToFreeze} hittades inte.` });
        }

        const action = is_active ? "aktiverats" : "frysts";
        return res.status(200).json({ message: `Userskonto med ID ${userIdToFreeze} har ${action}.` });

    } catch (err) {
        console.error("Fel vid frysning/aktivering av konto:", err);
        return res.status(500).json({ message: "Internt serverfel vid uppdatering av userstatus." });
    }
});

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
