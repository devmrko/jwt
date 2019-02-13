package jwt.hello;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
public class JwtRoles {
	
	// private static final Logger logger = LoggerFactory.getLogger(JwtRoles.class);

	Map<String, List<String>> urlRole = new HashMap<String, List<String>>();
	
	public JwtRoles() {
		
		// TODO it's set for test usage
		List<String> curUserRoleList = new ArrayList<String>();
		curUserRoleList.add("/greeting");
		this.urlRole.put("USER", curUserRoleList);
		
		List<String> curAdminRoleList = new ArrayList<String>();
		curAdminRoleList.add("/greeting");
		curAdminRoleList.add("/hello");
		this.urlRole.put("ADMIN", curAdminRoleList);
		
	}

}
