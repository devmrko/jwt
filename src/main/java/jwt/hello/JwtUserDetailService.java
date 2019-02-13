package jwt.hello;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JwtUserDetailService implements UserDetailsService {
	
	@Value("${jwt.testuser.name}")
	private String username;
	
	@Value("${jwt.testuser.pass}")
	private String password;

	@Value("${jwt.testuser.role}")
	private String role;

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO add retrieving logic to get user's info by username
		return new User(username, encoder().encode(password), getAuthority(username));
	}
	
	private Set<SimpleGrantedAuthority> getAuthority(String username) {
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		// securityUser.getRoles().forEach(role -> {
		// data에 role을 붙여서 관리중이라 role + 를 빼먹음
		//	authorities.add(new SimpleGrantedAuthority(role.getId()));
		// });
		// TODO add get authorities by username
		// add dummy role
		authorities.add(new SimpleGrantedAuthority(role));
		return authorities;
	}
	
	public Authentication getAuthentication(String username) {
		// TODO get user credential from persistence
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password, getAuthority(username));
		return authenticationManager.authenticate(token);
	}
	
	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
}
