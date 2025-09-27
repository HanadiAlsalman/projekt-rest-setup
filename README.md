# projekt-rest-setup
Gruppuppgift - Blug
Beskrivning
Företaget Blug, ska lansera ett nytt forum, och söker hjälp med att utveckla sin produkt. Blug’s vision är att vara en forumssida, där det finns olika Forum (kategorier), och varje forum kan innehålla olika trådar som är kopplade till forumets ämne. Blug kommer själva att utveckla klienten (frontend) internt och anlitar nu er för att ta fram en säker backend (server) som klienten kan ansluta till.
Er uppgift
Att bygga ut backend-delen till forumet och leverera ett REST-API, med högt fokus på säkerhet, som integreras med den befintliga klienten. Klienten kommer levereras löpande under projektets gång.
•	Utforma en MySQL-databas för forumets funktioner.
•	Implementera ett REST-API som följer god praxis, hög säkerhet och som stödjer forumets behov.
Forumet ska ha segmentering av innehåll och användare, med forum, trådar och inlägg. Användare kan ha olika roller och rättigheter:
Oinloggade användare
•	Registrera sig och bli medlem.
•	Kan endast se alla forum och trådar, samt gå in och läsa alla publika trådar.
Registrerade medlemmar
•	Ska få lov att skapa, redigera och radera sina egna inlägg, trådar och sin egen profil.
•	Kunna skapa nytt forum.
•	När en användare skapar en ny tråd, blir den användaren moderator för den tråden.
Moderatorer
•	Kan välja om tråden är publik eller privat.
•	Kan bjuda in men också ta bort användare till/från sina trådar.
•	Kan blockera eller ta bort innehåll från sina trådar.
•	Kan utse andra användare till hjälpmoderatorer, men också kunna ta tillbaka den rättigheten.
•	Ska kunna överlämna huvudansvaret över tråden till en annan användare.
Administratörer
•	Skapas direkt i databasen.
•	De kan blockera/radera användare, forum, trådar och inlägg, samt återställa blockerade objekt.
Ni får diskutera detaljerna kring roller och rättigheter med produktägaren innan implementation.
Genomförande
•	Arbeta i grupper och följ agila principer.
•	Planera ert arbete så att det finns tydliga specifikationer för databasstrukturen och API:ets endpoints.
•	Visualisera ert arbete (exempelvis med Trello eller liknande).
•	Arbetssätt i Git:
o	Varje ny funktionalitet ska utvecklas i en egen feature branch.
o	När en feature är färdigutvecklad och testad ska den mergas till en gemensam release branch.

