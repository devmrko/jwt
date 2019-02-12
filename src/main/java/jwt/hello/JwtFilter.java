package jwt.hello;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;

@Component
public class JwtFilter extends OncePerRequestFilter {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

	private final String ACCESS_TOKEN_NAME = "x-access-token";	
	
	public JwtFilter(JwtProvider jwtProvider) {
		this.jwtProvider = jwtProvider;
	}
	
//	@Autowired
	private JwtProvider jwtProvider;
	

	private void resetAuthenticationAfterRequest() {
		SecurityContextHolder.getContext().setAuthentication(null);
	}

	/* (non-Javadoc)
	 * @see org.springframework.web.filter.OncePerRequestFilter#doFilterInternal(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			String jwt = request.getHeader(ACCESS_TOKEN_NAME);
			if (StringUtils.hasText(jwt)) {
				if (this.jwtProvider.validateToken(jwt)) {
					Authentication authentication = this.jwtProvider.getAuthentication(jwt);
					SecurityContextHolder.getContext().setAuthentication(authentication);
				}
			}
			filterChain.doFilter(request, response);

			this.resetAuthenticationAfterRequest();
		} catch (ExpiredJwtException eje) {
			logger.info("### ### ### Security exception for user {} - {}", eje.getClaims().getSubject(), eje.getMessage());
			//((HttpServletResponse) servletResponse).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			
			request.setAttribute("message", "expired");
			// response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "expired");
			
			// logger.debug("### ### ### Exception " + eje.getMessage(), eje);
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
