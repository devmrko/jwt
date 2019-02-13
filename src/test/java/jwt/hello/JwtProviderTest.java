package jwt.hello;

import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.junit4.SpringRunner;


@RunWith(SpringRunner.class)
@SpringBootTest
public class JwtProviderTest {
	
	// private static final Logger logger = LoggerFactory.getLogger(JwtProviderTest.class);
	
	@Autowired
	JwtProvider jwtProvider;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Value("${jwt.adminuser.name}")
	private String username;
	
	@Value("${jwt.adminuser.pass}")
	private String password;

	@Value("${jwt.adminuser.role}")
	private String role;
	
	@Test
	public void test() {
		
		JwtUser jwtUser = new JwtUser();
		jwtUser.setUsername(username);
		jwtUser.setRoles(role);
		
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(jwtUser.getRoles());
		List<SimpleGrantedAuthority> updatedAuthorities = new ArrayList<SimpleGrantedAuthority>();
		updatedAuthorities.add(authority);
		
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(jwtUser.getUsername(), password, updatedAuthorities);
		Authentication authentication = authenticationManager.authenticate(token);
		
		JwtTokenDetail jwtTokenDetail = jwtProvider.generateJwtToken(authentication, jwtUser);
		assertNotNull(jwtTokenDetail.getAccessToken());
		assertNotNull(jwtTokenDetail.getRefreshToken());
		
	}

}
