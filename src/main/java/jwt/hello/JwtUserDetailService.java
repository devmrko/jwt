package jwt.hello;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class JwtUserDetailService implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		// TODO add retrieving logic to get user's info by username
		String userName = "admin";
		String password = "hist1234";
				
		return new User(userName, password, getAuthority(userName));
	}
	
	private Set<SimpleGrantedAuthority> getAuthority(String username) {
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		// securityUser.getRoles().forEach(role -> {
		// data에 role을 붙여서 관리중이라 role + 를 빼먹음
		//	authorities.add(new SimpleGrantedAuthority(role.getId()));
		// });
		// TODO add get authorities by username
		// add dummy role
		authorities.add(new SimpleGrantedAuthority("ADMIN"));
		return authorities;
	}
	
}
