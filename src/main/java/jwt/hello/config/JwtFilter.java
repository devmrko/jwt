package jwt.hello.config;

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
import jwt.hello.service.JwtProvider;
import jwt.hello.vo.JwtErrorCodes;

@Component
public class JwtFilter extends OncePerRequestFilter {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

	private final String ACCESS_TOKEN_NAME = "x-access-token";	
	
	@Autowired
	private JwtProvider jwtProvider;
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>reset SecurityContextHolder authentication 
	     * </ul>
	     *  
	     */
	private void resetAuthenticationAfterRequest() {
		SecurityContextHolder.getContext().setAuthentication(null);
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>apply authentication in SecurityContextHolder
	     * </ul>
	     *  
	     * @param authentication
	     */
	private void applyAuthenticationAfterRequest(Authentication authentication) {
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	/**
     * <B>History</B>
     * <ul>
     * <li>Date : 2019. 2. 15.
     * <li>Developer : devmrko
     * <li>customize filter logic to apply JWT token validation
     * </ul>
     *  
     * @param authentication
     */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		try {
			String jwtStr = request.getHeader(ACCESS_TOKEN_NAME);
			if (StringUtils.hasText(jwtStr)) {
				this.jwtProvider.validateJwtToken(jwtStr);
				Authentication authentication = jwtProvider.getJwtAuthentication(jwtStr);
				jwtProvider.checkUrlByRole(request, authentication);
				applyAuthenticationAfterRequest(authentication);
			}
			filterChain.doFilter(request, response);
			this.resetAuthenticationAfterRequest();
			
		} catch (ExpiredJwtException ex) {
			logger.error("### ### ### JwtFilter - ExpiredJwtException: {}", ex.getMessage());
			// request.setAttribute("message", JwtErrorCodes.CSC_JWT_EXPIRED);
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_JWT_EXPIRED.toString());
			
		} catch (MalformedJwtException ex) {
			logger.error("### ### ### JwtFilter - MalformedJwtException: {}", ex.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_TOKEN.toString());
			
		} catch (Exception ex) {
			Throwable t = ex.getCause();
			logger.info("### ### ### JwtFilter - Exception - {}", t.getMessage());
			switch (t.getMessage()) {
		    case "CSC_CANNOT_REFRESH":
		    	customSendError(response, JwtErrorCodes.CSC_CANNOT_REFRESH);
		    	break;
		    case "CSC_BAD_CREDENTIALS":
		    	customSendError(response, JwtErrorCodes.CSC_BAD_CREDENTIALS);
		    	break;
		    case "CSC_URL_FORBIDDEN":
		    	customSendError(response, JwtErrorCodes.CSC_URL_FORBIDDEN);
		    	break;
		    case "CSC_UNAUTHORIZED":
		    	customSendError(response, JwtErrorCodes.CSC_UNAUTHORIZED);
		    	break;
			};
			
		}
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>handle response when expected error is occurred
	     * </ul>
	     *  
	     * @param response
	     * @param jwtErrorCodes
	     * @throws IOException
	     */
	public void customSendError(HttpServletResponse response, JwtErrorCodes jwtErrorCodes) throws IOException {
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, jwtErrorCodes.toString());
	}
	
}
