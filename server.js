import express from 'express';
import mysql from 'mysql2/promise';
import dbCredentials from './db-credentials.js';
import session from "express-session"
import crypto from "crypto"
import acl from "./acl.js"
import bcrypt from 'bcrypt'; // npm install bcrypt
import rateLimit from 'express-rate-limit'; // npm install express-rate-limit



const app = express();
const port = 3000;

app.use(express.json());
// access control list middleware
//app.use(acl)


// 1. Grundläggande Rate Limit (Global)
// Tillåter 100 anrop per IP var 15:e minut för alla endpoints (förutom de som har en striktare limit)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minuter
    max: 100, // Max 100 anrop per IP
    message: "För många anrop från denna IP, försök igen om 15 minuter."
});

// 2. Strikt limit för känsliga anrop (Registrering/Login)
// Tillåter endast 5 anrop var 5:e minut per IP, vilket är bra mot massregistrering.
const strictLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minuter
    max: 5, // Max 5 anrop per IP
    message: JSON.stringify({ message: "För många registreringsförsök från denna IP, vänta 5 minuter innan du försöker igen." }),
    standardHeaders: true,
    legacyHeaders: false,
});

// 3. Admin Limit för administrativa funktioner
// Mycket strikt limit, 5 anrop per timme.
const adminLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 timme
    max: 5, // Max 5 anrop per IP per timme
    message: JSON.stringify({ message: "För många administrativa anrop från denna IP, vänta en timme innan du försöker igen." }),
    standardHeaders: true,
    legacyHeaders: false,
});

// 4. Profiluppdatering (5 gånger per timme)
const profileUpdateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 timme
    max: 5, // Max 5 anrop per IP per timme
    message: JSON.stringify({ message: "Du har uppnått max antal profiluppdateringar (5/timme). Försök igen senare." }),
    standardHeaders: true,
    legacyHeaders: false,
});


app.use(session({
  secret: process.env.HASH_COOK, // en hemlig nyckel för att signera session-cookie
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

// Hashfunktion , crypto säkerhetnivå är låg till medel
function hash(word) {
  const salt = process.env.HASH_SALT
  return crypto.pbkdf2Sync(word, salt, 1000, 64, "sha512").toString("hex")
}

/*
// för hög säkerhet nivå används bcrypto
// https://medium.com/@bhupendra_Maurya/password-hashing-using-bcrypt-e36f5c655e09
const saltRounds = 10; // Högre värde ger bättre säkerhet, men långsammare

// Ny registrering:
const passwordHash = await bcrypt.hash(password, saltRounds);

// Ny inloggning:
const match = await bcrypt.compare(password, user.password_hash);
if (!match) {  Fel lösenord  }*/


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

app.get('/check-session', apiLimiter, (req, res) => {
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
app.post("/api/users/register", strictLimiter, async (req, res) => {
  const { username, email, password, birth_date } = req.body
    //   // Kontrollerar längd för både användarnamn och lösenord
  if (!username || username.length < 3 || username.length > 50 ||
      !email ||
      !password || password.length < 8 ||
      !birth_date) {
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
    return res.status(500).json({ message: "Internal Server Error" }) // för att undvika informationsläckage
  }
})


// 2. Logga in
app.post("/api/users/login", strictLimiter, async (req, res) => {
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
    return res.status(500).json({ message: "Internal Server Error" })//för att undvika informationsläckage
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
      return res.status(500).json({ message: "Internal Server Error" })
    }

    return res.json({ message: "Du är utloggad." })
  })
})

// 4. Hämta inloggad användares profil
app.get("/api/users/profil", apiLimiter, async (req, res) => {
  //ACL: kontrollera att user måste vara inloggad (user, moderator, admin)
  if (!req.session.user) {
    return res.status(401).json({ message: "Du är inte inloggad." })
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
    return res.status(500).json({ message: "Internal Server Error" }) // för att förhindra informationsläckage.
  }
})

// 5. Uppdatera egen profil (Email & Lösenord)
app.put("/api/users/profil", profileUpdateLimiter, async (req, res) => {

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
        return res.status(500).json({ message: "Internal Server Error" });
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
    return res.status(500).json({ message: "Internal Server Error" });
  }
})

// 7. Frys/aktivera userskonto, admins roll
// ACL: admins roll
app.put("/api/admin/users/freeze/:id", adminLimiter, async (req, res) => {

    // ACL: måste vara inloggad
    if (!req.session.user) {
        return res.status(401).json({ message: "Åtkomst nekad. Du är inte inloggad." });
    }

    // ACL: måste vara admin
    if (req.session.user.role !== "admin") {
        return res.status(403).json({ message: `Åtkomst nekad. Din roll (${req.session.user.role}) är inte tillräcklig, det kräver roll: admin` });
    }

    const adminId = req.session.user.id // fånga inloggad admins id
    // Hämta ID som sträng från URL
    const userIdToFreezeRaw = req.params.id;

   // Försök konvertera till heltal (integer)
   const userIdToFreeze = parseInt(userIdToFreezeRaw, 10);

   //Kontrollera strikt att den ursprungliga strängen
  // inte innehöll några skräptecken efter numret.
  if (userIdToFreeze.toString() !== userIdToFreezeRaw) {
     // Detta fångar "2-3" eftersom 2.toString() är "2", men userIdToFreezeRaw är "2-3"
     return res.status(400).json({ message: "Ogiltigt användar-ID i URL. Endast heltal tillåts." });
}

   // Kontrollera att konverteringen lyckades och att ID är ett positivt nummer
   if (isNaN(userIdToFreeze) || userIdToFreeze <= 0) {
    return res.status(400).json({ message: "Ogiltigt användar-ID i URL" });
   }
    const { is_active, reason } = req.body; // kräv en anledning

    // Validera inmatning
    if (typeof is_active !== 'boolean') {
         return res.status(400).json({ message: "Status måste vara true (aktiv) eller false (frys)." });
    }

    // kräv en anledning för administrativa åtgärder
    if (!reason || reason.trim().length<5) {
        return res.status(400).json({message: "En kort anledning (minst 5 tecken) krävs för denna åtgärd."})
    }

    // ACL: Förhindra att admin fryser sitt eget konto
    if (String(userIdToFreeze) === String(req.session.user.id)) {
        return res.status(403).json({ message: "Du kan inte ändra statusen på ditt eget administratörskonto." });
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
        // hård ACL: Lägg till Revisionsspår (Auditing)
        console.log(`Admin ID ${adminId} har ${action} konto ID ${userIdToFreeze}. Anledning: ${reason}`);

        return res.status(200).json({ message: `Userskonto med ID ${userIdToFreeze} har ${action}.` });

    } catch (err) {
        console.error("Fel vid frysning/aktivering av konto:", err);
        return res.status(500).json({ message: "Internal Server Error" });
    }
});

// Forums
//1. Skapa forum (kräver inloggning)
app.post("/api/forums/create", apiLimiter, async (req, res) => {
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
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

//2. alla kan se forum, ingen inloggning krävs
app.get("/api/forums", apiLimiter, async (req, res) => {
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
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

//3. Hämtar forum baserat på namn
app.get("/api/forums/search", apiLimiter, async (req, res) => {
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
    return res.status(500).json({ message: "Internal Server Error" });
  }
});


// Threads
//1. Skapa threads (lägg in user som moderator direkt), kräver inloggning
app.post("/api/threads/create", apiLimiter, async (req, res) => {
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
app.get("/api/threads", apiLimiter, async (req, res) => {
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
    return res.status(500).json({ message: "Internal Server Error" });
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
app.post("/api/threads/:id/moderators", apiLimiter, async (req, res) => {
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
    return res.status(500).json({ message: "Internal Server Error" }); // för att undvika att avslöja känsliga databasdetaljer.
  }
});

// 5. Ta bort som soft delete en moderator från en tråd
app.delete("/api/threads/:id/moderators/:userId", apiLimiter, async (req, res) => {
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
    return res.status(500).json({ message: "Internal Server Error" });// för att undvika att avslöja känsliga databasdetaljer.
  }
});







app.listen(port, () => {
  console.log(`Servern körs på http://localhost:${port}`);
});
