package jwt.hello;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;

@Component
public class JwtFilter extends OncePerRequestFilter {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

	private final String ACCESS_TOKEN_NAME = "x-access-token";	
	
	public JwtFilter(JwtProvider jwtProvider) {
		this.jwtProvider = jwtProvider;
	}
	
	@Autowired
	private JwtProvider jwtProvider;
	
	private void resetAuthenticationAfterRequest() {
		SecurityContextHolder.getContext().setAuthentication(null);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			String jwt = request.getHeader(ACCESS_TOKEN_NAME);
			if (StringUtils.hasText(jwt)) {
				this.jwtProvider.validateToken(jwt);
				Authentication authentication = jwtProvider.getAuthentication(jwt);
				jwtProvider.checkUrlByRole(request, authentication);
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
			filterChain.doFilter(request, response);
			this.resetAuthenticationAfterRequest();
			
		} catch (ExpiredJwtException eje) {
			logger.error("### ### ### ExpiredJwtException - Security exception for user {} - {}", eje.getClaims().getSubject(), eje.getMessage());
			request.setAttribute("message", JwtErrorCodes.CSC_JWT_EXPIRED);
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_JWT_EXPIRED.toString());
			
		} catch (MalformedJwtException ex) {
			logger.error("### ### ### MalformedJwtException - Security exception for user {}", ex.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_TOKEN.toString());
			
		} catch (Exception ex) {
			Throwable t = ex.getCause();
			logger.info("### ### ### Exception - {}", t.getMessage());
			switch (t.getMessage()) {
		    case "CSC_CANNOT_REFRESH":
		    	response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_CANNOT_REFRESH.toString());
		    	break;
		    case "CSC_BAD_CREDENTIALS":
		    	response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_CREDENTIALS.toString());
		    	break;
		    case "CSC_URL_FORBIDDEN":
		    	response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_URL_FORBIDDEN.toString());
		    	break;
		    case "CSC_UNAUTHORIZED":
		    	response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_UNAUTHORIZED.toString());
		    	break;
			};
			
		}
	}
	
}
