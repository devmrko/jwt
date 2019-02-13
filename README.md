# JWT token example by Spring Boot 2

## Configuration
- Run JwtProviderTest to get JWT access key, and refresh key, default access time is 10 min
- Send RESTful request with JWT access key, JWT filter will check JWT access key, and send proper HTTP status
  - If it's necessary check RESTful URL by role in the JWT token payload whether it's qualified or not
- If HTTP 401 message is received(CSC_JWT_EXPIRED), the error handling of front-end page has to send refresh request to get fresh JWT access key

## Work flow
- Getting JWT access key
- JWT access key is expired(getting 401 HTTP status, and CSC_JWT_EXPIRED message), and try to get JWT access key
- Getting new JWT access key by refresh key
  - Send refresh request, and if refresh key isn't used, then send new JWT access key
- Check the requested URL, and role in JWT token payload

## Error flow
- Getting JWT access key
  - Id, or password is wrong, bad credentials, then send 401 status, and CSC_BAD_CREDENTIALS message
- JWT access key is expired
- Getting new JWT access key by refresh key
  - If it's after 60 min, then send 401 status, and CSC_CANNOT_REFRESH message
  - Send refresh request, and if refresh key is already used, then send 401 status, and CSC_CANNOT_REFRESH message
- Check the requested URL, and role in JWT token payload
  - if the URL isn't qualified by the role, then send 401 status, and CSC_UNAUTHORIZED message

## Test case
- log-in request
  - admin case(POST, http://localhost:8080/rest/auth/login)
  - request body below(it's mocked by source, and you can change it by your persistence later)
```
  {
    "username": "admin",
    "password": "admin1234"
  }
```
  - guest(another user) case(POST, http://localhost:8080/rest/auth/login)
  - request body below(it's mocked by source, and you can change it by your persistence later)
```
  {
    "username": "guest",
    "password": "guest1234"
  }
```
- refresh request
  - case(POST, http://localhost:8080/rest/auth/refresh)
  - after refresh token used, can't use it again
  - request body below
```
  {
    "accessToken": "",
    "refreshToken": ""
  }
```
- RESTful URL authentication test(mock each role, and has specific URLs)
  - greeting request which is valid for both of users
    - case(GET, http://localhost:8080/greeting)
  - hello request which is valid for only admin, not for guest
    - case(GET, http://localhost:8080/hello)
  