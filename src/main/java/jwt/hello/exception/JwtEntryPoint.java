package jwt.hello.exception;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

// should be declare it as component for accessing by WebSecurityConfig bean
@Component
public class JwtEntryPoint implements AuthenticationEntryPoint {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtEntryPoint.class);

	@Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
		
		final String expiredMsg = (String) request.getAttribute("message");
		final String msg = (expiredMsg != null) 
				? expiredMsg
				: ("Bad credentials".equals(authException.getMessage().toString()) ? "CSC_BAD_CREDENTIALS" : "CSC_UNAUTHORIZED");
		
		logger.info("### ### ### JwtEntryPoint - commence - {}", msg);
		
		switch (msg) {
		case "CSC_JWT_EXPIRED":
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
			break;
		case "CSC_BAD_CREDENTIALS":
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
			break;
		case "CSC_URL_FORBIDDEN":
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
			break;
		case "CSC_BAD_TOKEN":
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
			break;	
		case "CSC_UNAUTHORIZED":
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, msg);
			break;
		}
		
    }
	
}
