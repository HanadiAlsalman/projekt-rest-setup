import { readFileSync } from "fs"

// Rollnamn för globala roller i databas
const global_roles = ['user', 'admin'];

const accessList = JSON.parse(
  readFileSync(new URL("./access-list.json", import.meta.url))
)

//Access Control List (ACL) Middleware.
//Kontrollerar om den inloggade användaren har behörighet
export default function acl(request, response, next){

  // 1. Bestäm användarens roller
  const userRoles = ["*"] // Alla har '*' behörighet som standard

  const sessionRole = request.session?.user?.role

  if(sessionRole && global_roles.includes(sessionRole)){
    userRoles.push(sessionRole) // Lägg till 'user' eller 'admin'
  } else {
    userRoles.push("anonymous") // Lägg till 'anonymous' om inte inloggad/okänd
  }

  // 2. for loop genom access-listan för att hitta en match
  for(const route of accessList){

    // Använder request.path för att matcha mot "url" i JSON
    if(route.url === request.path){

      // Hitta en accessregel som matchar metoden och rollen
      for(const access of route.accesses){

        // Matchar metoden (POST, GET, PUT, DELETE)
        const methodMatches = access.methods.includes(request.method)

        // Matchar rollen  mellan användarens roller och regelns roller
        const roleMatches = userRoles.some(userRole => access.roles.includes(userRole))

        if(roleMatches && methodMatches){
          // Åtkomst beviljad
          return next()
        }
      }
    }
  }

  // Om loopen slutar utan matchning, nekas åtkomst
  return response.status(403).json({message:"Åtkomst nekad. Otillräcklig behörighet."})

}