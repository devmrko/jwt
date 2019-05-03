package jwt.hello.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
	
	public void test(int n, int[] ar) {
		Map<Integer, Integer> colorPair = new HashMap<Integer, Integer>();
        for(int i = 0; i < n; i++) {
            if(checkColorIdx(colorPair, ar[i]) == -1) {
                colorPair.put(ar[i], 0);
            } else {
            	colorPair.replace(ar[i], colorPair.get(ar[i]) + 1);
            }
        }
	}
	
	int getPairOfSocks(Map<Integer, Integer> colorPair) {
		int result = 0;
		for(Map.Entry<Integer, Integer> entry : colorPair.entrySet()) {
			result += (entry.getValue() / 2);
		}
		return result;
	}
	
	int checkColorIdx(Map<Integer, Integer> colorPair, int colorNo) {
		for(Map.Entry<Integer, Integer> entry : colorPair.entrySet()) {
			int key = entry.getKey();
			if(key == colorNo) {
				return key;
			}
		}
        return -1;
    }
	
	public void test2(int n, String s) {
		List<String> result = new ArrayList<String>();
		result.add("-");
		int idx = 0;
		for(int i = 0; i < s.length(); i++) {
			if("U".equals(s.substring(i, 1))) {
				if(isAbled(result, idx, "U")) {
					idx = idx - 1;
					for(int j = 0; j < result.size(); j++) {
						if(j == idx) {
							result.add(j, result.get(j) + "/");
						} else {
							result.add(j, result.get(j) + " ");
						}
					}
				} else {
					List<String> replace = new ArrayList<String>();
					replace.add(returnEmptySpace(i) + "/");
					for(int j = 0; j < result.size(); j++) {
						replace.add(result.get(j));
					}
					result = replace;
					idx = idx -1;
				}
				
			} else if("D".equals(s.substring(i, 1))) {
				if(isAbled(result, idx, "D")) {
					idx = idx + 1;
					for(int j = 0; j < result.size(); j++) {
						if(j == idx) {
							result.add(j, result.get(j) + "\\");
						} else {
							result.add(j, result.get(j) + " ");
						}
					}
				} else {
					for(int j = 0; j < result.size(); j++) {
						result.add(j, result.get(j) + " ");
					}
					result.add(returnEmptySpace(i) + "\\");
					idx = idx + 1;
				}
			}
		}
	}
	
	String returnEmptySpace(int n) {
		String result = "";
		for(int i = 0; i < n; i++) {
			result += " ";
		}
		return result;
	}
	
	boolean isAbled(List<String> result, int idx, String type) {
		if("U".equals(type)) {
			return 0 >= idx -1;
		} else if("D".equals(type)) {
			return result.size() >= idx +1;
		}
		System.out.println();
		return false;
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
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain)
			throws ServletException, IOException {
		
		if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
			res.setHeader("Access-Control-Allow-Origin", "*");
			res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE");
			res.setHeader("Access-Control-Allow-Credentials", "true");
			res.setHeader("Access-Control-Allow-Headers",
					"Content-Type, Accept, X-Requested-With, remember-me, x-access-token");
			res.setHeader("Access-Control-Request-Headers", "x-access-token");
			res.setHeader("Access-Control-Expose-Headers", "Content-Length, Authorization");
		}

		try {
			String jwtStr = req.getHeader(accessTokenName);
			if (jwtStr == null) {
				JwtCustomException jwtCustomException = new JwtCustomException(JwtErrorCodes.CSC_WITHOUT_JWT,
						JwtErrorCodes.CSC_WITHOUT_JWT.toString());
				throw new Exception(JwtErrorCodes.CSC_WITHOUT_JWT.toString(), jwtCustomException);
			}

			if (StringUtils.hasText(jwtStr)) {
				this.jwtProvider.validateJwtToken(jwtStr);
				Authentication authentication = jwtProvider.getJwtAuthentication(jwtStr);
				this.jwtProvider.checkUrlByRole(req, authentication);
				this.applyAuthenticationAfterRequest(authentication);
			}
			this.resetAuthenticationAfterRequest();
			filterChain.doFilter(req, res);

		} catch (ExpiredJwtException ex) {
			logger.error("### ### ### - ExpiredJwtException: {}", ex.getMessage());
			// request.setAttribute("message", JwtErrorCodes.CSC_JWT_EXPIRED);
			res.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_JWT_EXPIRED.toString());

		} catch (MalformedJwtException ex) {
			logger.error("### ### ### - MalformedJwtException: {}", ex.getMessage());
			res.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_TOKEN.toString());

		} catch (Exception ex) {
			Throwable t = ex.getCause();
			if (t != null) {
				logger.info("### ### ### - Exception - {}", t.getMessage());

				switch (t.getMessage()) {
				case "CSC_CANNOT_REFRESH":
					customSendError(res, JwtErrorCodes.CSC_CANNOT_REFRESH);
					break;
				case "CSC_BAD_CREDENTIALS":
					customSendError(res, JwtErrorCodes.CSC_BAD_CREDENTIALS);
					break;
				case "CSC_URL_FORBIDDEN":
					customSendError(res, JwtErrorCodes.CSC_URL_FORBIDDEN);
					break;
				case "CSC_UNAUTHORIZED":
					customSendError(res, JwtErrorCodes.CSC_UNAUTHORIZED);
					break;
				case "CSC_WITHOUT_JWT":
					customSendError(res, JwtErrorCodes.CSC_WITHOUT_JWT);
					break;
				}
				;
			} else {
				res.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
			}
		}

	}
	
	// filter에 사용하지 않을 url 패턴 설정
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
