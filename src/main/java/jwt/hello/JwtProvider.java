package jwt.hello;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;

@Component
public class JwtProvider implements Serializable {

	private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

	@Autowired
	JwtUtil jwtUtil;
	
	@Autowired
	JwtRoles jwtRoles;

	private static final long serialVersionUID = 373250939562443193L;

	private final String JWT_SECRET = "topas-art-local";

	private final String JWT_AUTHORITY = "role";

	@Value("${jwt.accesstime}")
	private long JWT_ACCESSKEY_VALID_DURATION;

	public UsernamePasswordAuthenticationToken getJwtAuthentication(final String token, final Authentication auth,
			final String username) {
		logger.info("### ### ### JwtProvider - getAuthentication");

		JwtParser jwtParser = Jwts.parser().setSigningKey(JWT_SECRET);
		Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);
		try {
			Claims claims = claimsJws.getBody();
			Collection<? extends GrantedAuthority> authorities = Arrays
					.stream(claims.get(JWT_AUTHORITY).toString().split(",")).map(SimpleGrantedAuthority::new)
					.collect(Collectors.toList());
			return new UsernamePasswordAuthenticationToken(username, "", authorities);

		} catch (Exception ex) {
			logger.error(ex.getMessage());
		}

		return null;
	}

	public String getUsernameFromToken(String token) throws JwtCustomException, Exception {
		logger.info("### ### ### JwtProvider - getUsernameFromToken");
		return getClaimFromToken(token, Claims::getSubject);
	}

	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver)
			throws JwtCustomException, Exception {
		logger.info("### ### ### JwtProvider - getClaimFromToken");
		Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) throws JwtCustomException, Exception {
		logger.info("### ### ### JwtProvider - getAllClaimsFromToken");
		Claims returnClaim = null;
		try {
			returnClaim = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token).getBody();

		} catch (ExpiredJwtException ex) {
			logger.error("### ### ### getAllClaimsFromToken - ExpiredJwtException: {}", ex.getMessage());
			throw new JwtCustomException(JwtErrorCodes.CSC_JWT_EXPIRED, ex.getMessage());

		} catch (Exception ex) {
			logger.error("### ### ### getAllClaimsFromToken - Exception: {}", ex.getMessage());

		}
		return returnClaim;
	}

	public JwtTokenDetail generateJwtToken(Authentication authentication, JwtUser jwtUser) {
		logger.info("### ### ### JwtProvider - generateJwtToken");
		JwtTokenDetail jwtTokenDetail = new JwtTokenDetail();

		// current time basis(iat)
		long iat = jwtUtil.getIat();

		String accessJwtToken = new String(generateJwtAccessToken(authentication, iat));
		String refreshJwtTokenId = UUID.randomUUID().toString();
		String refreshJwtToken = new String(generateJwtRefreshToken(refreshJwtTokenId));

		logger.info("accessJwtToken Test [[ ");
		logger.info("{}", accessJwtToken);
		logger.info("]]");

		logger.info("refreshJwtToken Test [[ ");
		logger.info("{}", refreshJwtToken);
		logger.info("]]");

		jwtTokenDetail.setJwtUser(jwtUser);
		jwtTokenDetail.setAccessToken(accessJwtToken);
		jwtTokenDetail.setRefreshToken(refreshJwtToken);

		return jwtTokenDetail;
	}

	public String generateJwtAccessToken(Authentication authentication, long iat) {
		logger.info("### ### ### JwtProvider - generateJwtAccessToken");
		String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(","));
		String accessToken = Jwts.builder().setSubject(authentication.getName()).claim(JWT_AUTHORITY, authorities)
				.signWith(SignatureAlgorithm.HS512, JWT_SECRET).setIssuedAt(new Date(iat))
				.setExpiration(new Date(iat + JWT_ACCESSKEY_VALID_DURATION)).compact();
		return accessToken;
	}

	public String generateJwtRefreshToken(String uuid) {
		logger.info("### ### ### JwtProvider - generateJwtRefreshToken");
		Claims claims = Jwts.claims();
		claims.put("refreshTokenId", uuid);
		return Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS512, JWT_SECRET).compact();
	}

	public void validateToken(String authToken) {
		logger.info("### ### ### JwtProvider - validateToken:");
		try {
			JwtParser jwtParser = Jwts.parser().setSigningKey(JWT_SECRET);
			jwtParser.parseClaimsJws(authToken);
		} catch (SignatureException ex) {
			logger.info("### ### ### Invalid JWT signature: " + ex.getMessage());
			logger.debug("### ### ### Exception " + ex.getMessage(), ex);
			throw new JwtCustomException(JwtErrorCodes.CSC_BAD_TOKEN, "CSC_BAD_TOKEN");
		}
	}

	public Authentication getAuthentication(String token) {
		Claims claims = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token).getBody();
		Collection<? extends GrantedAuthority> authorities = Arrays
				.asList(claims.get(JWT_AUTHORITY).toString().split(",")).stream()
				.map(authority -> new SimpleGrantedAuthority(authority)).collect(Collectors.toList());
		User principal = new User(claims.getSubject(), "", authorities);

		logger.info("### ### ### JwtProvider - getAuthentication: iat({}), expiration({})",
				jwtUtil.getDatetime(claims.getIssuedAt().getTime()),
				jwtUtil.getDatetime(claims.getExpiration().getTime()));

		return new UsernamePasswordAuthenticationToken(principal, "", authorities);
	}

	public String getUsernameFromExpiredToken(String token) {
		String username = null;
		try {
			username = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token).getBody().getSubject();
		} catch (ExpiredJwtException e) {
			username = e.getClaims().getSubject();
		} catch (Exception ex) {
			logger.error("### ### ### JwtProvider - getUsernameFromExpiredToken: {}", ex.getMessage());
		}
		return username;
	}

	public void checkUrlByRole(HttpServletRequest request, Authentication authentication) throws Exception {
		
		Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();
		String path = request.getServletPath().toString();
		Iterator<? extends GrantedAuthority> itr = roles.iterator();
		
		boolean isUrlVerified = false;
		while (itr.hasNext()) {
			GrantedAuthority element = itr.next();
			List<String> curVerifiedUrlList = jwtRoles.getUrlRole().get(element.getAuthority());
			for(int i = 0; curVerifiedUrlList.size() > i; i++) {
				if(path.equals(curVerifiedUrlList.get(i))) {
					isUrlVerified = true;
				}
			}
		}
		
		if(!isUrlVerified) {
			JwtCustomException jwtCustomException = new JwtCustomException(JwtErrorCodes.CSC_URL_FORBIDDEN, JwtErrorCodes.CSC_URL_FORBIDDEN.toString());
			throw new Exception(JwtErrorCodes.CSC_URL_FORBIDDEN.toString(), jwtCustomException);
		}
	}
	
}
