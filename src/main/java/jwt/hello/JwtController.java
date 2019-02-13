package jwt.hello;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtController {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtController.class);

	@Autowired
	JwtProvider jwtProvider;

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	JwtUserDetailService jwtUserDetailService;
	
	@Autowired
	JwtRefreshKeys jwtRefreshKeys;
	
	@Value("${jwt.defaultrole}")
	private String defaultRole;
	
	@RequestMapping(method = RequestMethod.POST, path="/rest/auth/login")
	public JwtTokenDetail getAccessKeyByLoginRequest(@RequestBody JwtUser jwtUser) {

		// TODO role assign for real
		Collection<? extends GrantedAuthority> xxx = jwtUserDetailService.getAuthentication(jwtUser.getUsername()).getAuthorities();
		jwtUser.setRoles(StringUtils.collectionToDelimitedString(xxx, ","));

		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(jwtUser.getRoles());
		List<SimpleGrantedAuthority> updatedAuthorities = new ArrayList<SimpleGrantedAuthority>();
		updatedAuthorities.add(authority);
		JwtTokenDetail jwtTokenDetail = null;
		
		try {
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(jwtUser.getUsername(), jwtUser.getPassword(), updatedAuthorities);
			Authentication authentication = authenticationManager.authenticate(token);
			jwtTokenDetail = jwtProvider.generateJwtToken(authentication, jwtUser);
			jwtRefreshKeys.addJwtRefreshKey(jwtTokenDetail.getRefreshToken(), jwtUser.getUsername());
			
		} catch (BadCredentialsException ex) {
			logger.error("### ### ### JwtController - BadCredentialsException: {}", ex.getMessage());
			throw new BadCredentialsException(JwtErrorCodes.CSC_BAD_CREDENTIALS.toString());
		} catch (Exception ex) {
			logger.error("### ### ### JwtController - Exception: {}", ex.getMessage());
			throw new JwtCustomException(JwtErrorCodes.CSC_UNAUTHORIZED, JwtErrorCodes.CSC_UNAUTHORIZED.toString());
		}

		return jwtTokenDetail;
	}
	
	@RequestMapping(method = RequestMethod.POST, path="/rest/auth/refresh")
	public JwtTokenDetail getAccessKeyByRefreshKey(@RequestBody JwtKeys jwtKeys) throws Exception {
		
		logger.info("### ### ### JwtController - getAccessKeyByRefreshKey");
		
		JwtTokenDetail jwtTokenDetail = null;
		boolean refreshBool = true;
		String username = null;
		
		username = jwtProvider.getUsernameFromExpiredToken(jwtKeys.getAccessToken());
		
		if(username != null && jwtRefreshKeys.isJwtRefreshKeyAvailable(jwtKeys.getRefreshToken(), username)) {
			JwtUser jwtUser = new JwtUser();
			jwtUser.setUsername(username);
			
			// TODO role assign for real
			jwtUser.setRoles(defaultRole);

			SimpleGrantedAuthority authority = new SimpleGrantedAuthority(jwtUser.getRoles());
			List<SimpleGrantedAuthority> updatedAuthorities = new ArrayList<SimpleGrantedAuthority>();
			updatedAuthorities.add(authority);

			// refresh JWT token do not need to check, and input password
			jwtTokenDetail = jwtProvider.generateJwtToken(jwtUserDetailService.getAuthentication(jwtUser.getUsername()), jwtUser);
			
		} else {
			refreshBool = false;
		}
		
		if(!refreshBool) {
			logger.error("### ### ### JwtController - getAccessKeyByRefreshKey: CSC_CANNOT_REFRESH");
			JwtCustomException jwtCustomException = new JwtCustomException(JwtErrorCodes.CSC_CANNOT_REFRESH, JwtErrorCodes.CSC_CANNOT_REFRESH.toString());
			throw new Exception(JwtErrorCodes.CSC_CANNOT_REFRESH.toString(), jwtCustomException);
		}

		return jwtTokenDetail;
	}
	
}