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
	
	@Value("${jwt.guestuser.name}")
	private String guestUsername;
	
	@Value("${jwt.guestuser.pass}")
	private String guestPassword;

	@Value("${jwt.guestuser.role}")
	private String guestRole;
	
	@Value("${jwt.adminuser.name}")
	private String adminUsername;
	
	@Value("${jwt.adminuser.pass}")
	private String adminPassword;

	@Value("${jwt.adminuser.role}")
	private String adminRole;

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO add retrieving logic to get user's info by username
		User user = null;
		if("admin".equals(username)) {
			user = new User(adminUsername, encoder().encode(adminPassword), getAuthority(adminUsername));
		} else if("guest".equals(username)) {
			user = new User(guestUsername, encoder().encode(guestPassword), getAuthority(guestUsername));
		}
		
		return user;
	}
	
	private Set<SimpleGrantedAuthority> getAuthority(String username) {
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		// securityUser.getRoles().forEach(role -> {
		// data에 role을 붙여서 관리중이라 role + 를 빼먹음
		//	authorities.add(new SimpleGrantedAuthority(role.getId()));
		// });
		// TODO add get authorities by username
		// add dummy role
		if("admin".equals(username)) {
			authorities.add(new SimpleGrantedAuthority(adminRole));
		} else if("guest".equals(username)) {
			authorities.add(new SimpleGrantedAuthority(guestRole));
		}
		
		return authorities;
	}
	
	public Authentication getAuthentication(String username) {
		UsernamePasswordAuthenticationToken token = null;
		
		// TODO get user credential from persistence
		if("admin".equals(username)) {
			token = new UsernamePasswordAuthenticationToken(adminUsername, adminPassword, getAuthority(adminUsername));
		} else if("guest".equals(username)) {
			token = new UsernamePasswordAuthenticationToken(guestUsername, guestPassword, getAuthority(guestUsername));
		}
		
		return authenticationManager.authenticate(token);
	}
	
	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}
	
}
