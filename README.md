# JWT AS A SERVICE

### In this repository we built a jwt authentication and authorization (STATELESS AUTHENTICATION) then use Postman to test the end-points (API) using our generated Token (Access-Token and Refresh-Token).

### The Access-Token has generally a small expiration time (5 min e.g) and if we need to continue use the App, we need either to re-login or to refresh the Token. The latter is more flexible and user-friendly.
### For that, the use of an Refresh-Token allows to generate a new pair of Access-Token (useful for getting update from Database-Level, for example new Authorities have been granted) and 
### Refresh-Token (for continuing  working without going  back to the DB-Level).
### To rehresf the Token(use the GET Method) : localhost:8080/refreshToken.

### Here Postgres 12 is used as Databse.

### It is important to note that solutions like Auth02 implements JWT in a more flexible manner(as a standard). sometimes it's important to get your hands dirty with code to better understand how it works in depth.
