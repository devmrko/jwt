package jwt.hello;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtController {

	@Autowired 
	JwtProvider jwtProvider;
	
	 @Autowired
	 private AuthenticationManager authenticationManager;
	
	@RequestMapping("/rest/auth/getAccessKey")
	public JwtTokenDetail greeting(@RequestParam(value = "id") String id, @RequestParam(value = "password") String password) {
		
		JwtUser jwtUser = new JwtUser();
		jwtUser.setUsername(id);
		jwtUser.setRoles("ROLES_ADMIN");
		
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority(jwtUser.getRoles());
		List<SimpleGrantedAuthority> updatedAuthorities = new ArrayList<SimpleGrantedAuthority>();
		updatedAuthorities.add(authority);
		
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(jwtUser.getUsername(), password, updatedAuthorities);
		Authentication authentication = authenticationManager.authenticate(token);
		
		JwtTokenDetail jwtTokenDetail = jwtProvider.generateJwtToken(authentication, jwtUser);
		
		return jwtTokenDetail; 
	}
	
}