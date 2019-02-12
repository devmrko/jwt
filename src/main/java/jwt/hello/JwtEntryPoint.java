package jwt.hello;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ExceptionHandler;

// should be declare it as component for accessing by WebSecurityConfig bean
@Component
public class JwtEntryPoint implements AuthenticationEntryPoint {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtEntryPoint.class);

	@Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
		
		final String expiredMsg = (String) request.getAttribute("message");
		final String msg = (expiredMsg != null) ? expiredMsg : "Unauthorized";

		logger.info("### ### ### JwtEntryPoint - commence - Unauthorized - {}", msg);
		
		switch (expiredMsg) {
		case "expired":
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
			break;
		case "password_wrong":
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
			break;
		case "id_doesnot_exists":
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
			break;
		
		}
		
		
//	    final String msg = (expiredMsg != null) ? expiredMsg : "Unauthorized";
//	    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
		
        // This is invoked when user tries to access a secured REST resource without supplying any credentials
        // We should just send a 401 Unauthorized response because there is no 'login page' to redirect to
        // response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
	
	@ExceptionHandler(value = { JwtCustomException.class })
	public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         JwtCustomException authException) throws IOException {
		logger.info("### ### ### JwtEntryPoint - commence - JwtCustomException");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "ExpiredJwtException");
    }
	
}
