package jwt.hello.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jwt.hello.exception.JwtCustomException;
import jwt.hello.service.JwtProvider;
import jwt.hello.vo.JwtErrorCodes;

@Component
public class JwtFilter extends OncePerRequestFilter {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

	private String accessTokenName;	
	
	private String insecureUrlPattern;
	
	private JwtProvider jwtProvider;
	
	public JwtFilter(JwtProvider jwtProvider, @Value("${jwt.accessToken.name}") String accessTokenName, 
			@Value("${jwt.insecure.urlPattern}") String insecureUrlPattern) {
		this.jwtProvider = jwtProvider;
		this.accessTokenName = accessTokenName;
		this.insecureUrlPattern = insecureUrlPattern;
	}
	
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
			String jwtStr = request.getHeader(accessTokenName);
			if(jwtStr == null) {
				JwtCustomException jwtCustomException = new JwtCustomException(JwtErrorCodes.CSC_WITHOUT_JWT, JwtErrorCodes.CSC_WITHOUT_JWT.toString());
				throw new Exception(JwtErrorCodes.CSC_WITHOUT_JWT.toString(), jwtCustomException);
			}
			
			if (StringUtils.hasText(jwtStr)) {
				this.jwtProvider.validateJwtToken(jwtStr);
				Authentication authentication = jwtProvider.getJwtAuthentication(jwtStr);
				this.jwtProvider.checkUrlByRole(request, authentication);
				this.applyAuthenticationAfterRequest(authentication);
			}
			filterChain.doFilter(request, response);
			this.resetAuthenticationAfterRequest();
			
		} catch (ExpiredJwtException ex) {
			logger.error("### ### ### - ExpiredJwtException: {}", ex.getMessage());
			// request.setAttribute("message", JwtErrorCodes.CSC_JWT_EXPIRED);
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_JWT_EXPIRED.toString());
			
		} catch (MalformedJwtException ex) {
			logger.error("### ### ### - MalformedJwtException: {}", ex.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_TOKEN.toString());
			
		} catch (Exception ex) {
			Throwable t = ex.getCause();
			if(t != null) {
				logger.info("### ### ### - Exception - {}", t.getMessage());
			
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
				case "CSC_WITHOUT_JWT":
					customSendError(response, JwtErrorCodes.CSC_WITHOUT_JWT);
					break;
				};
			} else {
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
			}
		}
	}
	
	@Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith(insecureUrlPattern);
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
