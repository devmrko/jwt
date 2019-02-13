package jwt.hello;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
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
				
				Authentication authentication = this.jwtProvider.getAuthentication(jwt);
				
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
			filterChain.doFilter(request, response);

			this.resetAuthenticationAfterRequest();
		} catch (ExpiredJwtException eje) {
			logger.error("### ### ### ExpiredJwtException - Security exception for user {} - {}", eje.getClaims().getSubject(), eje.getMessage());
			//((HttpServletResponse) servletResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			
			request.setAttribute("message", JwtErrorCodes.CSC_JWT_EXPIRED);
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_JWT_EXPIRED.toString());
			
			// logger.debug("### ### ### Exception " + eje.getMessage(), eje);
		} catch (BadCredentialsException ex) {
			logger.error("### ### ### BadCredentialsException - Security exception for user {}", ex.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_CREDENTIALS.toString());
			
		} catch (MalformedJwtException ex) {
			logger.error("### ### ### MalformedJwtException - Security exception for user {}", ex.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_TOKEN.toString());
		
		} catch (JwtCustomException ex) {
			logger.error("### ### ### BadCredentialsException - Security exception for user {}", ex.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_CREDENTIALS.toString());
			
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
		    case "CSC_UNAUTHORIZED":
		    	response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_UNAUTHORIZED.toString());
		    	break;
			};
			
//		    if (t != null && t instanceof JwtCustomException) {
//		    	JwtCustomException m = (JwtCustomException) t;
//		        //handle your exception.
//		    	
//		    	logger.error("### ### ### BadCredentialsException - Security exception for user {}", m.getCustomMessage());
//		    	response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_CREDENTIALS.toString());
//
//		    } else {
//		        //handle other cases
//		    }
//			
//			if (ex instanceof BadCredentialsException) {
//				logger.error("### ### ### BadCredentialsException - Security exception for user {}", ex.getMessage());
//				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_CREDENTIALS.toString());
//
//			} else {
//				logger.error("### ### ### Exception - Security exception for user {}", ex.getMessage());
//				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_UNAUTHORIZED.toString());
//				
//			}
			
		}
	}
	
//	@Override
//	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//			throws ServletException, IOException {
//		logger.info("### ### ### JwtFilter - doFilterInternal");
//		
//		// TODO verify authentication
//		String accessToken = request.getHeader(ACCESS_TOKEN_NAME);
//		String username;
//		try {
//			username = jwtProvider.getUsernameFromToken(accessToken);
//			UsernamePasswordAuthenticationToken authentication = jwtProvider.getJwtAuthentication(accessToken,
//					SecurityContextHolder.getContext().getAuthentication(), username);
//			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//			logger.info("### ### ### authenticated user " + username + ", setting security context");
//			SecurityContextHolder.getContext().setAuthentication(authentication);
//		} catch (JwtCustomException ex) {
//			// TODO set response to send specific code, expiration
//			// TODO set response to send specific code, not valid
//			// TODO set response to send specific code, username not exists
//			logger.error("### ### ### doFilterInternal - JwtCustomException: {}", ex.getMessage());
//			switch (ex.getErrorCode()) {
//		    case EXPIRED:
//		    	// response.setStatus(411);
//		    	request.setAttribute("message", "expired");
//		    	break;
//		    case PASSWORD_WRONG:
//		    	request.setAttribute("message", "password_wrong");
//		    	// response.setStatus(403);
//		    	break;
//		    case ID_NOT_EXISTS:
//		    	request.setAttribute("message", "id_doesnot_exists");
//		    	// response.setStatus(403);
//		    	break;
//			}
//			
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		
//		
//		filterChain.doFilter(request, response);
//		
//	}
	
}
