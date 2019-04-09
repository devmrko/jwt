package jwt.hello.service;

import java.io.Serializable;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import jwt.hello.exception.JwtCustomException;
import jwt.hello.mapper.JwtMapper;
import jwt.hello.mock.JwtRefreshKeys;
import jwt.hello.mock.JwtRoles;
import jwt.hello.vo.JwtErrorCodes;
import jwt.hello.vo.JwtKeys;
import jwt.hello.vo.JwtTokenDetail;
import jwt.hello.vo.JwtUser;

@Component
public class JwtProvider implements Serializable {

	private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

	@Autowired
	JwtUtil jwtUtil;

	@Autowired
	JwtRoles jwtRoles;

	@Autowired
	JwtMapper jwtMapper;

	@Autowired
	JwtUserDetailService jwtUserDetailService;

	@Autowired
	JwtRefreshKeys jwtRefreshKeys;

	private static final long serialVersionUID = 373250939562443193L;

	private final String JWT_SECRET = "topas-art-local";

	private final String JWT_AUTHORITY = "role";

	@Value("${jwt.accesstime}")
	private long JWT_ACCESSKEY_VALID_DURATION;

	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>create JWT access, and refresh keys
	     * </ul>
	     *  
	     * @param authentication
	     * @param jwtUser
	     * @return
	     */
	public JwtTokenDetail generateJwtToken(Authentication authentication, JwtUser jwtUser) {
		
		logger.debug("### ### ### generateJwtToken");
		
		JwtTokenDetail jwtTokenDetail = new JwtTokenDetail();

		// current time basis(iat)
		long iat = jwtUtil.getIat();

		String accessJwtToken = new String(generateJwtAccessToken(authentication, iat));
		String refreshJwtToken = new String(generateJwtRefreshToken());

		logger.debug("accessJwtToken Test [[ ");
		logger.debug("{}", accessJwtToken);
		logger.debug("]]");

		logger.debug("refreshJwtToken Test [[ ");
		logger.debug("{}", refreshJwtToken);
		logger.debug("]]");

		jwtTokenDetail.setJwtUser(jwtUser);
		jwtTokenDetail.setAccessToken(accessJwtToken);
		jwtTokenDetail.setRefreshToken(refreshJwtToken);

		return jwtTokenDetail;
	}

	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>create JWT access token
	     * </ul>
	     *  
	     * @param authentication
	     * @param iat
	     * @return
	     */
	public String generateJwtAccessToken(Authentication authentication, long iat) {
		logger.debug("### ### ### generateJwtAccessToken");
		String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
		String accessToken = Jwts.builder().setSubject(authentication.getName()).claim(JWT_AUTHORITY, authorities)
				.signWith(SignatureAlgorithm.HS512, JWT_SECRET).setIssuedAt(new Date(iat))
				.setExpiration(new Date(iat + JWT_ACCESSKEY_VALID_DURATION)).compact();
		return accessToken;
	}

	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>create JWT refresh token
	     * </ul>
	     *  
	     * @return
	     */
	public String generateJwtRefreshToken() {
		logger.debug("### ### ### generateJwtRefreshToken");
		Claims claims = Jwts.claims();
		claims.put("refreshTokenId", UUID.randomUUID().toString());
		return Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS512, JWT_SECRET).compact();
	}

	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>validate JWT token by JwtParser
	     * </ul>
	     *  
	     * @param token
	     */
	public void validateJwtToken(String token) {
		logger.debug("### ### ### validateJwtToken:");
		try {
			JwtParser jwtParser = Jwts.parser().setSigningKey(JWT_SECRET);
			jwtParser.parseClaimsJws(token);
		} catch (SignatureException ex) {
			logger.error("### ### ### validateJwtToken - SignatureException: {}", ex.getMessage());
			throw new JwtCustomException(JwtErrorCodes.CSC_BAD_TOKEN, "CSC_BAD_TOKEN");
		}
	}

	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>get Authentication from JWT token
	     * </ul>
	     *  
	     * @param token
	     * @return
	     */
	public Authentication getJwtAuthentication(String jwtStr) {
		Claims claims = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(jwtStr).getBody();
		Collection<? extends GrantedAuthority> authorities = Arrays
				.asList(claims.get(JWT_AUTHORITY).toString().split(",")).stream()
				.map(authority -> new SimpleGrantedAuthority(authority)).collect(Collectors.toList());
		User user = new User(claims.getSubject(), "", authorities);

		logger.debug("### ### ### JwtProvider - getAuthentication: iat({}), expiration({})",
				jwtUtil.getDatetime(claims.getIssuedAt().getTime()),
				jwtUtil.getDatetime(claims.getExpiration().getTime()));

		return jwtUserDetailService.getUsernamePasswordAuthenticationToken(user, "", authorities);
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : Joungmin
	     * <li>여기에 Method 관련 설명을 기록한다.
	     * </ul>
	     *  
	     * @param token
	     * @return
	     */
	public String getUsernameFromToken(String token) {
		logger.debug("### ### ### getUsernameFromToken");
		String username = null;
		try {
			username = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token).getBody().getSubject();
		} catch (ExpiredJwtException e) {
			username = e.getClaims().getSubject();
		} catch (Exception ex) {
			logger.error("### ### ### getUsernameFromToken: {}", ex.getMessage());
		}
		return username;
	}

	/**
	 * <B>History</B>
	 * <ul>
	 * <li>Date : 2019. 2. 15.
	 * <li>Developer : devmrko
	 * <li>check request URL, and method whether it's qualified by role
	 * </ul>
	 * 
	 * @param request
	 * @param authentication
	 * @throws Exception
	 */
	public void checkUrlByRole(HttpServletRequest request, Authentication authentication) throws Exception {

		Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();
		
		String path = request.getRequestURL().toString();
		String method = request.getMethod().toString();
		URL aURL = new URL(path);

		Iterator<? extends GrantedAuthority> itr = roles.iterator();

		boolean isUrlVerified = false;
		while (itr.hasNext()) {
			GrantedAuthority element = itr.next();
			if(jwtMapper.selectIsUrlEnabled(aURL.getPath().replaceAll("/backoffice/", "").replaceAll("/", ""), method, element.getAuthority()) == 1) {
				isUrlVerified = true;
				break;
			}
		}

		if (!isUrlVerified) {
			logger.info("### it's not verified");
			JwtCustomException jwtCustomException = new JwtCustomException(JwtErrorCodes.CSC_URL_FORBIDDEN, JwtErrorCodes.CSC_URL_FORBIDDEN.toString());
			throw new Exception(JwtErrorCodes.CSC_URL_FORBIDDEN.toString(), jwtCustomException);
		} else {
			logger.info("### it's verified");
		}
		
	}

	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>get JWT access, and refresh token
	     * </ul>
	     *  
	     * @param jwtUser
	     * @param request
	     * @return
	     */
	public JwtTokenDetail getJwtTokens(JwtUser jwtUser, HttpServletRequest request) {
		logger.debug("### ### ### getJwtTokens");

		JwtTokenDetail jwtTokenDetail = null;

		try {
			jwtTokenDetail = this.generateJwtToken(jwtUserDetailService.getAuthentication(jwtUser), jwtUser);
			
			jwtMapper.insertRefreshToken(jwtTokenDetail.getRefreshToken(), jwtUser.getUsername());
			//jwtRefreshKeys.addJwtRefreshKey(jwtTokenDetail.getRefreshToken(), jwtUser.getUsername());

		} catch (BadCredentialsException ex) {
			logger.error("### ### ### BadCredentialsException: {}", ex.getMessage());
			throw new BadCredentialsException(JwtErrorCodes.CSC_BAD_CREDENTIALS.toString());
			
		} catch (Exception ex) {
			logger.error("### ### ### Exception: {}", ex.getMessage());
			throw new JwtCustomException(JwtErrorCodes.CSC_UNAUTHORIZED, JwtErrorCodes.CSC_UNAUTHORIZED.toString());
			
		}
		return jwtTokenDetail;
	}

	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>create JWT access, and refresh token by expired access, and fresh refresh tokens 
	     * </ul>
	     *  
	     * @param jwtKeys
	     * @param request
	     * @return
	     * @throws Exception
	     */
	public JwtTokenDetail getJwtTokenByRefresh(JwtKeys jwtKeys, HttpServletRequest request) throws Exception {
		logger.debug("### ### ### getJwtTokenByRefresh");

		JwtTokenDetail jwtTokenDetail = null;
		boolean refreshBool = true;
		String username = null;
		username = this.getUsernameFromToken(jwtKeys.getAccessToken());

		int used = jwtMapper.updateRefreshTokenAsUsed(jwtKeys.getRefreshToken(), username);
		
		if (username != null && used == 1) {
			JwtUser jwtUser = new JwtUser();
			jwtUser.setUsername(username);
			jwtTokenDetail = this.generateJwtToken(jwtUserDetailService.getUsernamePasswordAuthenticationToken(username), jwtUser);
		} else {
			refreshBool = false;
		}

		if (!refreshBool) {
			logger.error("### ### ### getJwtTokenByRefresh: CSC_CANNOT_REFRESH");
			JwtCustomException jwtCustomException = new JwtCustomException(JwtErrorCodes.CSC_CANNOT_REFRESH, JwtErrorCodes.CSC_CANNOT_REFRESH.toString());
			throw new Exception(JwtErrorCodes.CSC_CANNOT_REFRESH.toString(), jwtCustomException);
		}
		return jwtTokenDetail;
	}

}
