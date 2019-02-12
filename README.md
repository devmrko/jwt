# JWT token example by Spring Boot 2

## Configuration
- Run JwtProviderTest to get JWT access key, and refresh key, default access time is 10 min
- Send RESTful request with JWT access key, JWT filter will check JWT access key, and send proper HTTP status
  - If it's necessary check RESTful URL by role in the JWT token payload whether it's qualified or not
- If HTTP 401 message is received(jwt_expired), the error handling of front-end page has to send refresh request to get fresh JWT access key

## Work flow
- Getting JWT access key
- JWT access key is expired(getting 401 HTTP status, and jwt_expired message)
  - If it's before 60 min, then ask JWT access key again
- Getting new JWT access key by refresh key
  - Send refresh request, and if refresh key isn't used, then send new JWT access key
- Check the requested URL, and role in JWT token payload

## Error flow
- Getting JWT access key
  - Id, or password is wrong, bad credentials, then send 401 status, and login_failed message
- JWT access key is expired
  - If it's after 60 min, then send 401 status, and jwt_key_acquire_failed message
- Getting new JWT access key by refresh key
  - Send refresh request, and if refresh key is used, then send 401 status, and cannot_refresh_jwt message
- Check the requested URL, and role in JWT token payload
  - if the URL isn't qualified by the role, then send 401 status, and not_authorized message
