package jwt.hello;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
public class JwtRefreshKeys {
	
	private static final Logger logger = LoggerFactory.getLogger(JwtRefreshKeys.class);

	List<JwtRefreshKey> jwtRefreshKeys = new ArrayList<JwtRefreshKey>();
	
	public boolean isJwtRefreshKeyAvailable(String refreshKey, String username) {
		JwtRefreshKey curJwtRefreshKey = null;
		boolean keyAvailBool = false;
		
		for(int i = 0; jwtRefreshKeys.size() > i; i++) {
			curJwtRefreshKey = jwtRefreshKeys.get(i);
			logger.info("### ### ### JwtRefreshKeys - isJwtRefreshKeyUsed: {} - {} - {}", curJwtRefreshKey.getJwtRefreshKey(), curJwtRefreshKey.getUsername(), curJwtRefreshKey.getUseYn());
			if(refreshKey.equals(curJwtRefreshKey.getJwtRefreshKey()) && "N".equals(curJwtRefreshKey.getUseYn()) && username.equals(curJwtRefreshKey.getUsername())) {
				curJwtRefreshKey.setUseYn("Y");
				return true;
			}
		}
		return keyAvailBool;
	}
	
	public void addJwtRefreshKey(String refreshKey, String username) {
		JwtRefreshKey jwtRefreshKey = new JwtRefreshKey();
		jwtRefreshKey.setJwtRefreshKey(refreshKey);
		jwtRefreshKey.setUseYn("N");
		jwtRefreshKey.setUsername(username);
		jwtRefreshKeys.add(jwtRefreshKey);
	}

	public void setJwtRefreshKeyAsUsed(String refreshKey, String username) {
		JwtRefreshKey curJwtRefreshKey = null;
		for(int i = 0; jwtRefreshKeys.size() > 0; i++) {
			curJwtRefreshKey = jwtRefreshKeys.get(i);
			if(refreshKey.equals(curJwtRefreshKey.getJwtRefreshKey()) && "N".equals(curJwtRefreshKey.getUseYn()) && username.equals(curJwtRefreshKey.getUsername())) {
				curJwtRefreshKey.setUseYn("Y");
			}
		}
	}

	@Getter
	@Setter
	public static class JwtRefreshKey {
		private String jwtRefreshKey;
		private String username;
		private String useYn;
	}

}
